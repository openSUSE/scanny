module Scanny
  module Checks
    class ResetSessionCheck < Check
      def pattern
        pattern_reset_session
      end

      def check(node)
        issue :info, warning_message, :cwe => 384
      end

      private

      def warning_message
        "Improper resetting the session may lead to security problems"
      end

      def pattern_reset_session
        "Send<name = :reset_session>"
      end
    end
  end
end