require "spec_helper"

module Scanny::Checks
  describe ValidatesCheck do
    before do
      @runner = Scanny::Runner.new(ValidatesCheck.new)
      @message = "Incorrect validations may allow malicious data transmission"
      @issue = issue(:info, @message, 0)
    end

    it "reports \"validates_presence_of :email\" correctly" do
      @runner.should check("validates_presence_of :email").with_issue(@issue)
    end

    it "reports \"validates_uniqueness_of :username\" correctly" do
      @runner.should check("validates_uniqueness_of :username").with_issue(@issue)
    end
  end
end
