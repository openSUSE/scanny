module Scanny
  class Report
    attr_accessor :checks_performed, :nodes_inspected, :issues
    attr_reader   :file

    def initialize file
      @file             = file
      @checks_performed = 0
      @nodes_inspected  = 0
      @issues           = []
    end

    def to_s
      string =  "#{@file} [#{@checks_performed} checks done | "
      string += "#{nodes_inspected} nodes inspected | #{@issues.size} issues]"

      @issues.each do |issue|
        string += "\n  - #{issue.to_s}"
      end
      string
    end
  end
end
