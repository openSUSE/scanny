require 'rexml/document'

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

    def to_xml
      out = ""
      doc = REXML::Document.new

      testsuite = REXML::Element.new("testsuite")
      testsuite.add_attributes('assertions' => @nodes_inspected.to_s,
                               'errors'     => @issues.size.to_s,
                               'skipped'    => '0',
                               'tests'      => @checks_performed.to_s,
                               'failures'   => '0',
                               'name'       => @file)
      #TODO: track time?

      @issues.each do |issue|
        testcase = REXML::Element.new 'testcase'
        testcase.add_attributes("name" => "#{issue.file}:#{issue.line}")

        error = REXML::Element.new 'error'
        error.add_attributes('type'    => issue.impact.to_s,
                             'message' => issue.message)
        error.text = issue.to_s

        testcase.add_element error
        testsuite.add_element testcase
      end
      testsuite.add_element REXML::Element.new("system-out")
      testsuite.add_element REXML::Element.new("system-err")

      doc << testsuite
      doc.write(out, 2)
      out
    end
  end
end
