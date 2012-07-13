require "spec_helper"

module Scanny
  module Reporters
    describe SimpleReporter do
      describe "report" do
        describe "no issues" do
          it "returns correctly formatted string" do
            checks_performed = 5
            nodes_inspected  = 10

            reporter = SimpleReporter.new
            reporter.file             = 'foo.rb'
            reporter.checks_performed = checks_performed
            reporter.nodes_inspected  = nodes_inspected

            reporter.report.should == "foo.rb [#{checks_performed} checks done | "\
                                    "#{nodes_inspected} nodes inspected | "\
                                    "0 issues]"
          end
        end

        describe "has issues" do
          it "returns correctly formatted string" do
            checks_performed = 5
            nodes_inspected  = 10

            reporter = SimpleReporter.new
            reporter.file             = 'foo.rb'
            reporter.checks_performed = checks_performed
            reporter.nodes_inspected  = nodes_inspected
            reporter.issues << Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 43)
            reporter.issues << Issue.new("unsecure.rb", 43, :high, "Hey, I found unsecure code!", 43)

            expected_string = <<-EOT
foo.rb [#{checks_performed} checks done | #{nodes_inspected} nodes inspected | 2 issues]
  - [high] unsecure.rb:42: Hey, I found unsecure code! (CWE-43)
  - [high] unsecure.rb:43: Hey, I found unsecure code! (CWE-43)
            EOT
            reporter.report.should == expected_string.chomp
          end
        end
      end
    end
  end
end