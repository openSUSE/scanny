module Scanny
  module Checks
    class InputFilteringCheck < Check
      def pattern
        [
          pattern_terminal_escape_sequences,
          pattern_params
        ].join("|")
      end

      def check(node)
        issue :low, warning_message, :cwe => 20
      end

      def strict?
        true
      end

      private

      def warning_message
        "Possible injection vulnerabilities"
      end

      # params[:input]
      def pattern_params
        <<-EOT
          SendWithArguments<
            name = :[],
            receiver = Send<name = :params>
          >
        EOT
      end

      # system("\033]30;command\007")
      def pattern_terminal_escape_sequences
        <<-EOT
          StringLiteral<string *= /\\033\]30;.*\\007/>
        EOT
      end
    end
  end
end
