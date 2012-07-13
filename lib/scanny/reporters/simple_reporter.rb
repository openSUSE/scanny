require_relative 'reporter'

module Scanny
  module Reporters
    class SimpleReporter < Reporter
      def report
        string =  "#{file} [#{checks_performed} checks done | "
        string += "#{nodes_inspected} nodes inspected | #{issues.size} issues]"

        issues.each do |issue|
          string += "\n  - #{issue.to_s}"
        end
        puts string

        string
      end
    end
  end
end
