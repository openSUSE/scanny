module Scanny
  module Checks
    class TempFileOpenCheck < Check
      def pattern
        [
          pattern_temp,
          pattern_file_open,
          pattern_mkdir_p
        ].join("|")
      end

      def check(node)
        issue :medium, warning_message, :cwe => 377
      end

      private

      def warning_message
        "Access to the temporary files can lead to" +
        "unauthorized access to data"
      end

      # File.open("/app/path/tmp_file")
      def pattern_file_open
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                StringLiteral<string *= "tmp">
              ]
            >,
            receiver = ConstantAccess<name = :File>,
            name = :open
          >
        EOT
      end

      # mkdir_p("long/path/tmp/file")
      def pattern_mkdir_p
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                StringLiteral<string *= "tmp">
              ]
            >,
            name = :mkdir_p
          >
        EOT
      end

      def pattern_temp
        'StringLiteral<string *= /\/tmp\//>'
      end
    end
  end
end