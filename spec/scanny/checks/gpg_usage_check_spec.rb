require "spec_helper"

module Scanny::Checks
  describe GpgUsageCheck do
    before do
      @runner = Scanny::Runner.new(GpgUsageCheck.new)
      @message =  "Using gpg tool in the wrong way can lead to security problems"
      @issue = issue(:info, @message, 0)
    end

    it "reports \"GPG.method\" correctly" do
      @runner.should check("GPG.method").with_issue(@issue)
    end

    it "reports \"GPG.method\" correctly" do
      @runner.should check("Gpg.method").with_issue(@issue)
    end

    it "reports \"GPG.method\" correctly" do
      @runner.should check("GpgKey.method").with_issue(@issue)
    end

    it "reports \"system('gpg --example-flag')\" correctly" do
      @runner.should check("system('gpg --example-flag')").with_issue(@issue)
    end

    it "reports \"`gpg --example-flag`\" correctly" do
      @runner.should check("`gpg --example-flag`").with_issue(@issue)
    end
  end
end
