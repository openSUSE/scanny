require "spec_helper"

module Scanny
  module Checks
    module InsecureMethod
      describe MarshalCheck do
        before do
          @runner = Scanny::Runner.new(MarshalCheck.new)
          @message =  "Execute deserialize method can load to memory dangerous object"

          @issue = issue(:high, @message, 502)
        end

        it "reports \"object.deserialize\" correctly" do
          @runner.should check("Marshal.load(object)").with_issue(@issue)
          @runner.should check("load(object)").without_issues
        end

        it "reports \"deserialize('string')\" correctly" do
          @runner.should check("Marshal.restore(object)").with_issue(@issue)
          @runner.should check("restore(object)").without_issues
        end
      end
    end
  end
end