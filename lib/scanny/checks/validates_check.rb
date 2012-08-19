module Scanny
  module Checks
    class ValidatesCheck < Check
      def pattern
        pattern_validates
      end

      def check(node)
        issue :info, warning_message
      end

      def strict?
        true
      end

      private

      def warning_message
        "Incorrect validations may allow malicious data transmission"
      end

      # validates_presence_of :email
      def pattern_validates
        <<-EOT
        SendWithArguments<
          name *= /validates_[\\w]*_of/
        >
        EOT
      end
    end
  end
end