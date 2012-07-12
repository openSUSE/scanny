require_relative 'reporter'
require 'rexml/document'

module Scanny
  module Reporters
    class XMLReporter < Reporter

      def initialize(*)
        prepare_reports_directory
        super
      end

      def report
        out = ""
        doc = REXML::Document.new

        testsuite = REXML::Element.new("testsuite")
        testsuite.add_attributes('assertions' => nodes_inspected.to_s,
                                 'errors'     => issues.size.to_s,
                                 'skipped'    => '0',
                                 'tests'      => checks_performed.to_s,
                                 'failures'   => '0',
                                 'name'       => file)
        #TODO: track time?

        issues.each do |issue|
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
        File.open(output, "w") { |f| f.write(out) }

        out
      end

      private

      def output
        file_name = file.gsub('/', '\\')
        "reports/Test-#{file_name}.xml"
      end

      def prepare_reports_directory
        if File.exists?('reports')
          puts "Removing 'reports' directory"
          FileUtils.rm_rf 'reports'
        end
        FileUtils.mkdir 'reports'
      end
    end
  end
end
