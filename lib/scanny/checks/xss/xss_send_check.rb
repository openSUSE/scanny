module Scanny
  module Checks
    # Checks for send_* methods that are called with :disposition => 'inline'.
    # This can lead to download of private files from a server or to a XSS issue.
    class XssSendCheck < Check
      def pattern
        [
          pattern_send,
          pattern_send_with_param
        ].join("|")
      end

      def check(node)
        if Machete.matches?(node, pattern_send)
          issue :medium, warning_message, :cwe => [79, 115, 200]
        elsif Machete.matches?(node, pattern_send_with_param)
          issue :high, warning_message, :cwe => 201
        end
      end

      private

      def warning_message
        "Send file or data to client in \"inline\" " +
        "mode or with param can lead to XSS issues."
      end

      # send_file "file.txt", :disposition => "inline"
      # send_data "file.txt", :disposition => "inline"
      def pattern_send
        <<-EOT
        SendWithArguments<
          name = :send_file | :send_data,
          arguments = ActualArguments<
            array = [
              any,
              HashLiteral<
                array = [
                  any{even},
                  SymbolLiteral<value   = :disposition>,
                  StringLiteral<string  = "inline">,
                  any{even}
                ]
              >
            ]
          >
        >
        EOT
      end

      def pattern_send_with_param
        <<-EOT
        SendWithArguments<
          name = :send_file | :send_data,
          arguments = ActualArguments<
            array = [
              any*,
              SendWithArguments<
                name = :[],
                receiver = Send<name = :params>
              >,
              any*
            ]
          >
        >
        EOT
      end
    end
  end
end
