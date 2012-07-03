require "spec_helper"

module Scanny::Checks
  describe RandomNumbersCheck do
    before :each do
      @runner = Scanny::Runner.new(RandomNumbersCheck.new)
      @message = "This action indicates using low-entropy random number generator"
      @issue = issue(:medium, @message, 331)
    end

    it "reports \"Kernel.rand\" correctly" do
      @runner.should check('rand').with_issue(@issue)
      @runner.should check('Kernel.rand').with_issue(@issue)
      @runner.should check('Foo.rand').without_issues
      @runner.should check('foo.rand').without_issues
    end

    it "reports \"Kernel.srand\" correctly" do
      @runner.should check('srand').with_issue(@issue)
      @runner.should check('Kernel.srand').with_issue(@issue)
      @runner.should check('Foo.srand').without_issues
      @runner.should check('foo.srand').without_issues
    end

    it "reports calls with one argument only" do
      @runner.should check('rand').with_issue(@issue)
      @runner.should check('rand(42)').with_issue(@issue)
      @runner.should check('rand(42, 43, 44)').with_issue(@issue)
    end

    it "reports \"urandom\" usage" do
      @runner.should check('File.open("/dev/urandom")').with_issue(@issue)
      @runner.should check('urandom').without_issues
    end

    it "reports \"seed\" correctly" do
      @runner.should check('seed').with_issue(@issue)
      @runner.should check('seed(Time.now)').with_issue(@issue)
    end
  end
end
