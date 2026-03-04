// ABOUTME: Processor pipeline for intercepting connection I/O.
// ABOUTME: Supports filtering, bistream recording, and shellcode detection.

use std::any::Any;
use std::sync::Arc;

use crate::bistream::BiStream;
use crate::connection::Direction;

/// A processor that can observe and act on connection I/O data.
///
/// Processors are stored in a global template tree. Per-connection
/// instances are created by calling `new_ctx()` for each accepted connection.
pub trait Processor: Send + Sync {
    /// Name of this processor (for logging/config).
    fn name(&self) -> &str;

    /// Whether this processor applies to a connection with the given
    /// protocol name and connection type ("accept", "connect", "listen").
    fn accepts(&self, _protocol: &str, _conn_type: &str) -> bool {
        true
    }

    /// Called when data is received from the remote.
    fn io_in(&self, _ctx: &mut dyn ProcessorCtx, _data: &[u8]) {}

    /// Called when data is sent to the remote.
    fn io_out(&self, _ctx: &mut dyn ProcessorCtx, _data: &[u8]) {}

    /// Create per-connection state for this processor.
    fn new_ctx(&self) -> Box<dyn ProcessorCtx>;
}

/// Per-connection state held by a processor instance.
pub trait ProcessorCtx: Send {
    /// Downcast to concrete type.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// A node in the processor template tree (built from config, shared globally).
pub struct ProcessorNode {
    /// The processor implementation.
    pub processor: Arc<dyn Processor>,
    /// Child processors that run after this one.
    pub children: Vec<ProcessorNode>,
}

/// Per-connection instantiation of the processor tree after filtering.
pub struct ProcessorPipeline {
    nodes: Vec<ActiveNode>,
    bistream: Arc<BiStream>,
}

/// A filtered, instantiated processor node with per-connection context.
struct ActiveNode {
    processor: Arc<dyn Processor>,
    ctx: Box<dyn ProcessorCtx>,
    children: Vec<ActiveNode>,
}

impl ProcessorPipeline {
    /// Build a pipeline by walking the template tree and filtering out
    /// processors that don't accept this connection's protocol/type.
    pub fn from_tree(
        tree: &[ProcessorNode],
        protocol: &str,
        conn_type: &str,
    ) -> Self {
        let mut nodes = Vec::new();
        for template in tree {
            if let Some(active) = Self::instantiate(template, protocol, conn_type) {
                nodes.push(active);
            }
        }
        ProcessorPipeline {
            nodes,
            bistream: Arc::new(BiStream::new()),
        }
    }

    fn instantiate(
        template: &ProcessorNode,
        protocol: &str,
        conn_type: &str,
    ) -> Option<ActiveNode> {
        if !template.processor.accepts(protocol, conn_type) {
            return None;
        }

        let ctx = template.processor.new_ctx();
        let mut children = Vec::new();
        for child_template in &template.children {
            if let Some(child) = Self::instantiate(child_template, protocol, conn_type) {
                children.push(child);
            }
        }

        Some(ActiveNode {
            processor: Arc::clone(&template.processor),
            ctx,
            children,
        })
    }

    /// Feed incoming data through the pipeline.
    pub fn io_in(&mut self, data: &[u8]) {
        self.bistream
            .push(Direction::In, bytes::Bytes::copy_from_slice(data));
        for node in &mut self.nodes {
            Self::dispatch_in(node, data);
        }
    }

    /// Feed outgoing data through the pipeline.
    pub fn io_out(&mut self, data: &[u8]) {
        self.bistream
            .push(Direction::Out, bytes::Bytes::copy_from_slice(data));
        for node in &mut self.nodes {
            Self::dispatch_out(node, data);
        }
    }

    fn dispatch_in(node: &mut ActiveNode, data: &[u8]) {
        node.processor.io_in(&mut *node.ctx, data);
        for child in &mut node.children {
            Self::dispatch_in(child, data);
        }
    }

    fn dispatch_out(node: &mut ActiveNode, data: &[u8]) {
        node.processor.io_out(&mut *node.ctx, data);
        for child in &mut node.children {
            Self::dispatch_out(child, data);
        }
    }

    /// Access the bistream for this connection.
    pub fn bistream(&self) -> &Arc<BiStream> {
        &self.bistream
    }

    /// Whether the pipeline has any active processors.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }
}

// --- Filter Processor ---

/// A rule matching connection protocol and/or type.
#[derive(Debug, Clone)]
struct FilterRule {
    /// Protocol names to match (empty = any).
    protocols: Vec<String>,
    /// Connection types to match (empty = any). Values: "accept", "connect", "listen".
    conn_types: Vec<String>,
}

impl FilterRule {
    /// Check if this rule matches a given protocol and connection type.
    fn matches(&self, protocol: &str, conn_type: &str) -> bool {
        let proto_ok = self.protocols.is_empty() || self.protocols.iter().any(|p| p == protocol);
        let type_ok = self.conn_types.is_empty() || self.conn_types.iter().any(|t| t == conn_type);
        proto_ok && type_ok
    }
}

/// Processor that filters which connections pass through to its children.
///
/// Must match at least one allow rule AND zero deny rules.
pub struct FilterProcessor {
    label: String,
    allow: Vec<FilterRule>,
    deny: Vec<FilterRule>,
}

impl FilterProcessor {
    /// Create a new filter processor.
    pub fn new(label: String, allow: Vec<(Vec<String>, Vec<String>)>, deny: Vec<(Vec<String>, Vec<String>)>) -> Self {
        FilterProcessor {
            label,
            allow: allow
                .into_iter()
                .map(|(protocols, conn_types)| FilterRule {
                    protocols,
                    conn_types,
                })
                .collect(),
            deny: deny
                .into_iter()
                .map(|(protocols, conn_types)| FilterRule {
                    protocols,
                    conn_types,
                })
                .collect(),
        }
    }
}

impl Processor for FilterProcessor {
    fn name(&self) -> &str {
        &self.label
    }

    fn accepts(&self, protocol: &str, conn_type: &str) -> bool {
        // Must match at least one allow rule (if any exist)
        let allowed = self.allow.is_empty()
            || self.allow.iter().any(|r| r.matches(protocol, conn_type));
        // Must not match any deny rule
        let denied = self.deny.iter().any(|r| r.matches(protocol, conn_type));
        allowed && !denied
    }

    fn io_in(&self, _ctx: &mut dyn ProcessorCtx, _data: &[u8]) {
        // Filters don't process data, they only gate children
    }

    fn io_out(&self, _ctx: &mut dyn ProcessorCtx, _data: &[u8]) {}

    fn new_ctx(&self) -> Box<dyn ProcessorCtx> {
        Box::new(EmptyCtx)
    }
}

/// No-op per-connection context for processors that don't need state.
struct EmptyCtx;

impl ProcessorCtx for EmptyCtx {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Filter tests ---

    #[test]
    fn filter_allow_all() {
        let filter = FilterProcessor::new("test".into(), vec![], vec![]);
        assert!(filter.accepts("httpd", "accept"));
        assert!(filter.accepts("smbd", "connect"));
    }

    #[test]
    fn filter_allow_by_type() {
        let filter = FilterProcessor::new(
            "test".into(),
            vec![(vec![], vec!["accept".into()])],
            vec![],
        );
        assert!(filter.accepts("httpd", "accept"));
        assert!(!filter.accepts("httpd", "connect"));
    }

    #[test]
    fn filter_allow_by_protocol() {
        let filter = FilterProcessor::new(
            "test".into(),
            vec![(vec!["httpd".into(), "smbd".into()], vec![])],
            vec![],
        );
        assert!(filter.accepts("httpd", "accept"));
        assert!(filter.accepts("smbd", "connect"));
        assert!(!filter.accepts("ftpd", "accept"));
    }

    #[test]
    fn filter_deny_overrides_allow() {
        let filter = FilterProcessor::new(
            "test".into(),
            vec![(vec![], vec!["accept".into()])],
            vec![(vec!["ftpdata".into()], vec![])],
        );
        assert!(filter.accepts("httpd", "accept"));
        assert!(!filter.accepts("ftpdata", "accept")); // denied
    }

    #[test]
    fn filter_multiple_allow_rules() {
        let filter = FilterProcessor::new(
            "test".into(),
            vec![
                (vec![], vec!["accept".into()]),
                (vec!["ftpctrl".into()], vec!["connect".into()]),
            ],
            vec![],
        );
        assert!(filter.accepts("httpd", "accept"));
        assert!(filter.accepts("ftpctrl", "connect"));
        assert!(!filter.accepts("httpd", "connect")); // not accepted
    }

    // --- Pipeline tests ---

    /// Simple counting processor for testing.
    struct CountingProcessor {
        name: String,
    }
    struct CountingCtx {
        in_count: usize,
        out_count: usize,
    }
    impl ProcessorCtx for CountingCtx {
        fn as_any_mut(&mut self) -> &mut dyn Any { self }
    }
    impl Processor for CountingProcessor {
        fn name(&self) -> &str { &self.name }
        fn new_ctx(&self) -> Box<dyn ProcessorCtx> {
            Box::new(CountingCtx { in_count: 0, out_count: 0 })
        }
        fn io_in(&self, ctx: &mut dyn ProcessorCtx, _data: &[u8]) {
            let ctx = ctx.as_any_mut().downcast_mut::<CountingCtx>().unwrap();
            ctx.in_count += 1;
        }
        fn io_out(&self, ctx: &mut dyn ProcessorCtx, _data: &[u8]) {
            let ctx = ctx.as_any_mut().downcast_mut::<CountingCtx>().unwrap();
            ctx.out_count += 1;
        }
    }

    #[test]
    fn pipeline_from_empty_tree() {
        let pipeline = ProcessorPipeline::from_tree(&[], "httpd", "accept");
        assert!(pipeline.is_empty());
    }

    #[test]
    fn pipeline_dispatches_io() {
        let tree = vec![ProcessorNode {
            processor: Arc::new(CountingProcessor { name: "counter".into() }),
            children: vec![],
        }];
        let mut pipeline = ProcessorPipeline::from_tree(&tree, "httpd", "accept");
        assert!(!pipeline.is_empty());

        pipeline.io_in(b"hello");
        pipeline.io_in(b"world");
        pipeline.io_out(b"response");

        // Verify bistream recorded everything
        assert_eq!(pipeline.bistream().len(), 3);
        assert_eq!(pipeline.bistream().total_bytes(Direction::In), 10);
        assert_eq!(pipeline.bistream().total_bytes(Direction::Out), 8);
    }

    #[test]
    fn pipeline_filters_by_protocol() {
        let filter = Arc::new(FilterProcessor::new(
            "filter".into(),
            vec![(vec!["smbd".into()], vec![])],
            vec![],
        ));
        let counter: Arc<dyn Processor> = Arc::new(CountingProcessor { name: "counter".into() });

        let tree = vec![ProcessorNode {
            processor: filter,
            children: vec![ProcessorNode {
                processor: counter,
                children: vec![],
            }],
        }];

        // smbd should pass the filter
        let pipeline = ProcessorPipeline::from_tree(&tree, "smbd", "accept");
        assert!(!pipeline.is_empty());

        // httpd should be filtered out
        let pipeline = ProcessorPipeline::from_tree(&tree, "httpd", "accept");
        assert!(pipeline.is_empty());
    }

    #[test]
    fn pipeline_nested_dispatch() {
        let parent: Arc<dyn Processor> = Arc::new(CountingProcessor { name: "parent".into() });
        let child: Arc<dyn Processor> = Arc::new(CountingProcessor { name: "child".into() });

        let tree = vec![ProcessorNode {
            processor: parent,
            children: vec![ProcessorNode {
                processor: child,
                children: vec![],
            }],
        }];

        let mut pipeline = ProcessorPipeline::from_tree(&tree, "httpd", "accept");
        pipeline.io_in(b"data");

        // Both parent and child should have been called (verified via bistream)
        assert_eq!(pipeline.bistream().len(), 1);
    }
}
