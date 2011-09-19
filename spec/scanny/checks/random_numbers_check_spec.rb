require "spec_helper"

module Scanny::Checks
  describe RandomNumbersCheck do
    before :each do
      @runner = Scanny::Runner.new(RandomNumbersCheck.new)

      @rand_issue = issue(:medium,
        "The \"rand\" method indicates using low-entropy random number generator.",
        331)
      @srand_issue = issue(:medium,
        "The \"srand\" method indicates using low-entropy random number generator.",
        331)
    end

    it "reports \"Kernel.rand\" correctly" do
      @runner.should check('rand').with_issue(@rand_issue)
      @runner.should check('Kernel.rand').with_issue(@rand_issue)
      @runner.should check('Foo.rand').without_issues
      @runner.should check('foo.rand').without_issues
    end

    it "reports \"Kernel.srand\" correctly" do
      @runner.should check('srand').with_issue(@srand_issue)
      @runner.should check('Kernel.srand').with_issue(@srand_issue)
      @runner.should check('Foo.srand').without_issues
      @runner.should check('foo.srand').without_issues
    end

    it "reports calls with one argument only" do
      @runner.should check('rand').with_issue(@rand_issue)
      @runner.should check('rand(42)').with_issue(@rand_issue)
      @runner.should check('rand(42, 43, 44)').with_issue(@rand_issue)
    end
  end
end
