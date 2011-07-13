module Scanny
  module Checks
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class XssCheck < Check
      def interesting_nodes
        [:call]
      end

      def evaluate_start_call(node)
        name = node[2]

        return unless node[2] == :send_file
        params = node_to_hash node.find_node(:arglist).find_node(:hash)
        if params[:disposition] == :inline
          add_issue :high, "XSS issue"
        end
       end

      def evaluate_end_call(node)
        # Nothing to do.
      end
    end
  end
end
