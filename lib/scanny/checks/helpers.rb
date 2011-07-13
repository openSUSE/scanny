module Scanny
  module Checks

    class ConversionError < StandardError
    end

    module Helpers
      def node_to_hash node
        unless node.is_a? Sexp
          raise ConversionError.new("node is not a Sexp object")
        end

        if node.sexp_type != :hash
          raise ConversionError.new("node type is not hash")
        end

        hash = {}
        i = 0
        while (i+1 < node.sexp_body.size)
          key   = node.sexp_body[i].sexp_body.sexp_type
          value = node.sexp_body[i+1].sexp_body.sexp_type
          hash[key] = value
          i += 2
        end
        hash
      end
    end
  end
end
