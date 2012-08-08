require "spec_helper"

module Scanny::Checks::SSL
  describe VerifyPeerCheck do
    before do
      @runner = Scanny::Runner.new(VerifyPeerCheck.new)
      @message =  "Change the value of of VERIFY_PEER" +
                  "can lead to faulty accepted certificate"
      @issue = issue(:info, @message)
    end

    it "reports \"OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE\" correctly" do
      @runner.should  check("OpenSSL::SSL::VERIFY_PEER = OpenSSL::SSL::VERIFY_NONE").
                      with_issue(@issue)
    end
  end
end
