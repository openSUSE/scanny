require "spec_helper"

module Scanny::Checks::SystemTools
  describe GpgUsageCheck do
    before do
      @runner = Scanny::Runner.new(GpgUsageCheck.new)
      @message =  "Using gpg tool in the wrong way can lead to security problems"
      @issue = issue(:info, @message)
    end

    it "reports \"GPG.method\" correctly" do
      @runner.should check("GPG.method").with_issue(@issue)
    end

    it "reports \"Gpg.method\" correctly" do
      @runner.should check("Gpg.method").with_issue(@issue)
    end

    it "reports \"GpgKey.method\" correctly" do
      @runner.should check("GpgKey.method").with_issue(@issue)
    end

    it "reports \"GPGME.method\" correctly" do
      @runner.should check("GPGME.method").with_issue(@issue)
    end

    it "reports \"Gpgr.method\" correctly" do
      @runner.should check("Gpgr.method").with_issue(@issue)
    end

    it "reports \"RubyGpg.method\" correctly" do
      @runner.should check("RubyGpg.method").with_issue(@issue)
    end

    it "reports \"system('gpg --example-flag')\" correctly" do
      @runner.should check("system('gpg --example-flag')").with_issue(@issue)
    end

    it "reports \"`gpg --example-flag`\" correctly" do
      @runner.should check("`gpg --example-flag`").with_issue(@issue)
    end
  end
end
