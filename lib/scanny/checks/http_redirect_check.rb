module Scanny
  module Checks
    class HTTPRedirectCheck < Check
      def pattern
        [
          pattern_add_file_from_url,
          pattern_open_struct,
          pattern_open_uri,
          pattern_save_file
        ].join("|")
      end

      def check(node)
        issue :medium, warning_message, :cwe => 441
      end

      private

      def warning_message
        "HTTP redirects can be emitted by the Application"
      end

      # save_file()
      def pattern_save_file
        <<-EOT
          Send<name = :save_file>
          |
          SendWithArguments<name = :save_file>
        EOT
      end

      # add_file_from_url("http://example.com/file.txt")
      def pattern_add_file_from_url
        "SendWithArguments<name = :add_file_from_url>"
      end

      # require 'open-uri'
      def pattern_open_uri
        <<-EOT
          SendWithArguments<
            arguments = ActualArguments<
              array = [
                StringLiteral<string = 'open-uri'>
              ]
            >,
            name = :require
          >
        EOT
      end

      # OpenStruct.new(key: value)
      def pattern_open_struct
        <<-EOT
          Send<
            receiver = ConstantAccess<name = :OpenStruct>
          >
          |
          SendWithArguments<
            receiver = ConstantAccess<name = :OpenStruct>
          >
        EOT
      end
    end
  end
end