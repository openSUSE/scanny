module Scanny
  module Checks
    # TODO: change documentation
    # Checks for methods executing external commands that pass the command
    # through shell expansion. This can cause unwanted code execution if the
    # command includes unescaped input.
    class XssSendCheck < Check
      def pattern
        pattern_send
      end

      def check(node)
        issue :high, warning_message, :cwe => 79
      end

      private

      def warning_message
        "Send file or data to client in \"inline\" mode can lead to XSS issues."
      end

        #medium          CWE-79                  send_file.*:disposition\s*=>\s*\'inline\'
        #medium          CWE-79                  send_data.*:disposition\s*=>\s*\'inline\'
        def pattern_send
          <<-EOT
          SendWithArguments<
            name = :send_file | :send_data,
            arguments = ActualArguments<
              array = [
                HashLiteral<
                  array = [
                    SymbolLiteral<value   = :disposition>,
                    StringLiteral<string  = "inline">
                  ]
                >
              ]
            >
          >
          EOT
        end
    end
  end
end
