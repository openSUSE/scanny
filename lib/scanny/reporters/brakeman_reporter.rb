require_relative 'reporter'

# Example of output file for brakeman
#
# [FILE]  [LINE_NUMBER] [TYPE_OF_ISSUE] [PLACE_OF_ISSUE] [MESSAGE] [IMPACT]
# home.rb       22       HTTPRedirect      Controller      Issue     Weak
# sql.rb        50       SQLInjection      Model           Issue     Weak
# ...

module Scanny
  module Reporters
    class BrakemanReporter < Reporter
      def report
        result = ""

        issues.each do |issue|
          result << ("#{issue.file}\t"    +
                    "#{issue.line}\t"     +
                    "NO_TYPE\t"           +
                    "Project\t"           +
                    "#{issue.message}\t"  +
                    "#{issue.impact}\n")
        end

        result
      end

    end
  end
end