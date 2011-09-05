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

        # medium          CWE-79                  send_file.*:disposition\s*=>\s*\'inline\'
        # medium          CWE-79                  send_data.*:disposition\s*=>\s*\'inline\'
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
                issue :high, "XSS issue (CWE-79)"
              end
            end
          end
        end

        # high            CWE-79                  render_api_error.*params\s*\[
        if [:render_api_error].include? node.name
          return if node.arguments.size < 1
          node.arguments.array.each do |arg|
            next unless arg.is_a? Rubinius::AST::HashLiteral
            i = 0
            while(i + 1 < arg.array.size)
              key   = arg.array[i]
              value = arg.array[i + 1]
              i += 2
              next unless key.is_a? Rubinius::AST::SymbolLiteral
              next unless value.is_a? Rubinius::AST::StringLiteral
              if value.string =~ /params\s*\[/
                issue :high, "XSS issue (CWE-79)"
              end
            end
          end
        end

        # high            CWE-79                  flash\[\:warning\]\s*=\s*.*params\s*\[
        # medium          CWE-79                  flash\[\:warning\]\s*=\s*.*#\{
#         if name == :flash ??? XXX ???
#           params = node_to_hash node.find_node(:arglist).find_node(:hash)
#           if params[:disposition] == 'inline'
#             add_issue :high, "XSS issue (CWE-79)"
#           end
#         end

        #low             CWE-79                  logger.*params\s*\[
        if [:logger].include? node.name
          #end unless node.arguments.array.size < 1
          node.arguments.array.each do |arg|
            next unless arg.is_a? Rubinius::AST::HashLiteral
            i = 0
            while(i + 1 < arg.array.size)
              key   = arg.array[i]
              value = arg.array[i + 1]
              i += 2
              next unless key.is_a? Rubinius::AST::SymbolLiteral
              next unless value.is_a? Rubinius::AST::StringLiteral
              if value.string =~ /params\s*\[/
                issue :medium, "XSS issue (CWE-79)"
              end
            end
          end
        end
        
        #low             CWE-79                  logger.*#\{
        if [:logger].include? node.name
          #end unless node.arguments.array.size < 1
          node.arguments.array.each do |arg|
            next unless arg.is_a? Rubinius::AST::HashLiteral
            i = 0
            while(i + 1 < arg.array.size)
              key   = arg.array[i]
              value = arg.array[i + 1]
              i += 2
              next unless key.is_a? Rubinius::AST::SymbolLiteral
              next unless value.is_a? Rubinius::AST::StringLiteral
              if value.string =~ /#\{/
                issue :low, "XSS issue (CWE-79)"
              end
            end
          end
        end


      end
      
    end
  end
end
