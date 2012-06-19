module Scanny
  module Checks
    module InsecureMethod
      describe DeserializeMethodCheck do
        before do
          @runner = Scanny::Runner.new(DeserializeMethodCheck.new)
          @message =  "Execute deserialize method can load to memory dangerous object"

          @issue = issue(:high, @message, 502)
        end

        it "reports \"object.deserialize\" correctly" do
          @runner.should check("object.deserialize").with_issue(@issue)
        end

        it "reports \"deserialize('string')\" correctly" do
          @runner.should check("deserialize(string)").with_issue(@issue)
        end
      end
    end
  end
end