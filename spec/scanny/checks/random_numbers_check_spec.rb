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

    it "reports \"rand\" calls without a receiver" do
      @runner.should check('rand').with_issue(@rand_issue)
    end

    it "reports \"Kernel.rand\" calls" do
      @runner.should check('Kernel.rand').with_issue(@rand_issue)
    end

    it "does not report \"rand\" calls on other classes/modules" do
      @runner.should check('Foo.rand').without_issues
    end

    it "does not report \"rand\" calls on random objects" do
      @runner.should check('foo.rand').without_issues
    end

    it "reports \"srand\" calls without a receiver" do
      @runner.should check('srand').with_issue(@srand_issue)
    end

    it "reports \"Kernel.srand\" calls" do
      @runner.should check('Kernel.srand').with_issue(@srand_issue)
    end

    it "does not report \"srand\" calls on other classes/modules" do
      @runner.should check('Foo.srand').without_issues
    end

    it "does not report \"srand\" calls on random objects" do
      @runner.should check('foo.srand').without_issues
    end

    it "reports calls with no arguments" do
      @runner.should check('rand').with_issue(@rand_issue)
    end

    it "reports calls with one argument" do
      @runner.should check('rand(42)').with_issue(@rand_issue)
    end

    it "does not report calls with multiple arguments" do
      @runner.should check('rand(42, 43, 44)').with_issue(@rand_issue)
    end
  end
end
