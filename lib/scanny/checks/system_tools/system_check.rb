module Scanny
  module Checks
    module SystemTools
      class SystemCheck < Check
        private

        def check_usage_for(method)
        <<-EOT
          SendWithArguments
          <
            name = :system | :exec,
            arguments = ActualArguments<
              array = [
                any*,
                StringLiteral<string *= '#{method}'>,
                any*
              ]
            >
          >
          |
          ExecuteString<string *= '#{method}'>
        EOT
        end
      end
    end
  end
end