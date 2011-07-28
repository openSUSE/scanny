module Scanny
  module Checks
    # TODO: change documentation
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class XssCheck < Check
      def pattern
        'SendWithArguments'
      end

      def check(node)
        if [:send_file, :send_data].include? node.name
          node.arguments.array.each do |arg|
            next unless arg.is_a? Rubinius::AST::HashLiteral
            i = 0
            while(i + 1 < arg.array.size)
              key   = arg.array[i]
              value = arg.array[i + 1]
              i += 2
              next unless key.is_a? Rubinius::AST::SymbolLiteral 
              next unless key.value == :disposition
              next unless value.is_a? Rubinius::AST::StringLiteral
              if value.string == 'inline'
                add_issue :high, "XSS issue"
              end
            end
          end
        end
      end
    end
  end
end
