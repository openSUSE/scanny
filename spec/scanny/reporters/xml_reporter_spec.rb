require "spec_helper"

module Scanny
  module Reporters
    describe XMLReporter do
      describe "report" do
        describe "no issues" do
          it "returns correctly formatted string" do
            checks_performed = 5
            nodes_inspected  = 10

            report = XMLReporter.new
            report.file             = 'foo.rb'
            report.checks_performed = checks_performed
            report.nodes_inspected  = nodes_inspected

            doc = REXML::Document.new report.report
            doc.should_not have_xml('/testsuite/testcase')
          end
        end

        describe "has issues" do
          it "returns correctly formatted string" do
            file             = 'foo.rb'
            checks_performed = 5
            nodes_inspected  = 10

            report = XMLReporter.new
            report.file             = file
            report.checks_performed = checks_performed
            report.nodes_inspected  = nodes_inspected
            report.issues << Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 43)
            report.issues << Issue.new("unsecure.rb", 43, :high, "Hey, I found unsecure code!", 43)

            xpath_query = "/testsuite[@tests='#{checks_performed}' and "\
                                     "@skipped='0' and @failures='0' and "\
                                     "@assertions='#{nodes_inspected}' and "\
                                     "@name='#{file}']"
            report.report.should have_xml xpath_query

            report.issues.each do |issue|
              xpath_query = "//testcase[@name='#{issue.file}:#{issue.line}' and "\
                            "[error[@message='#{issue.message}' and "\
                                   "@type='#{issue.impact.to_s}']]]"
              report.report.should have_xml xpath_query
            end
          end
        end
      end
    end
  end
end