module Scanny
  module Checks
    module InsecureMethod
      describe EvalMethodCheck do
        before do
          @runner = Scanny::Runner.new(EvalMethodCheck.new)
          @message = "Execute eval method can lead the ruby interpreter to run dangerous code"

          @issue = issue(:high, @message, 95)
        end

        it "reports \"eval\" correctly" do
          @runner.should check("eval").without_issues
        end

        it "reports \"eval('ruby_code')\" correctly" do
          @runner.should check("eval('ruby_code')").with_issue(@issue)
        end
      end
    end
  end
end