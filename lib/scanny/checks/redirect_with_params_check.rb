module Scanny
  module Checks
    class RedirectWithParamsCheck < Check
      def pattern
        pattern_redirect
      end

      def check(node)
        issue :medium, warning_message, :cwe => [79, 113, 601, 698]
      end

      private

      def warning_message
        "Use of external parameters in redirect_to method" +
        "can lead to unauthorized redirects"
      end

      # redirect_to params[:input]
      def pattern_redirect
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                SendWithArguments<
                  name = :[],
                  receiver = Send<name = :params>
                >
              ]
            >,
            name = :redirect_to
          >
        EOT
      end
    end
  end
end