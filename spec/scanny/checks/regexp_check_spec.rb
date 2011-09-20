require "spec_helper"

module Scanny::Checks
  describe RegexpCheck do
    before :each do
      @runner = Scanny::Runner.new(RegexpCheck.new)
      @issue = issue(:low,
        "Possible improper regular expression usage.",
        [185, 625, 791])
    end

    it "reports regexps with starting with \"^\" or ending with \"$\" correctly" do
      @runner.should check('/^foo/').with_issue(@issue)
      @runner.should check('/foo$/').with_issue(@issue)
      @runner.should check('/foo/').without_issues

      @runner.should check('/^foo#{bar}baz/').with_issue(@issue)
      @runner.should check('/foo#{bar}baz$/').with_issue(@issue)
      @runner.should check('/foo#{bar}baz/').without_issues
    end
  end
end
