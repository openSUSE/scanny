require "spec_helper"

module Scanny
  module Reporters
    describe BrakemanReporter do
      describe "report" do
        describe "no issues" do
          it "returns correctly formatted string" do
            checks_performed = 5
            nodes_inspected  = 10

            reporter = BrakemanReporter.new
            reporter.file             = 'foo.rb'
            reporter.checks_performed = checks_performed
            reporter.nodes_inspected  = nodes_inspected

            reporter.report.should == ""
          end
        end

        describe "has issues" do
            it "returns correctly formatted string" do
              checks_performed = 5
              nodes_inspected  = 10

              reporter = BrakemanReporter.new
              reporter.file             = 'foo.rb'
              reporter.checks_performed = checks_performed
              reporter.nodes_inspected  = nodes_inspected
              reporter.issues << Issue.new("unsecure.rb", 42, :high, "Hey, I found unsecure code!", 43)
              reporter.issues << Issue.new("unsecure.rb", 43, :high, "Hey, I found unsecure code!", 43)

              expected_string = <<-EOT
unsecure.rb\t42\tNO_TYPE\tProject\tHey, I found unsecure code!\thigh
unsecure.rb\t43\tNO_TYPE\tProject\tHey, I found unsecure code!\thigh
              EOT
              reporter.report.should == expected_string
            end
          end
      end
    end
  end
end