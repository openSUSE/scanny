module Scanny
  class CheckingVisitor
    def initialize(checks, filename)
      @file     = filename
      @checks ||= {}
      checks.each do |check|
        nodes = check.interesting_nodes
        nodes.each do |node|
          @checks[node] ||= []
          @checks[node] << check
          @checks[node].uniq!
        end
      end
    end

    def send node_name, node, parent
      checks = @checks[node_name]
      return unless checks
      checks.each do |check|
        check.file = @file
        check.line = node.line
        check.evaluate_node(node)
      end
    end

    def visit(node)
      checks = @checks[node.node_type]
      checks.each {|check| check.evaluate_node_start(node)} unless checks.nil?

      node.visitable_children.each {|sexp| sexp.accept(self)}

      checks.each {|check| check.evaluate_node_end(node)} unless checks.nil?
    end
  end
end
