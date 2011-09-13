# 2011/09/12: common/lib/common/utils.rb
# Copyright © 2009 Novell, Inc.  All Rights Reserved.
#
# THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND TREATIES.
# IT MAY NOT BE USED, COPIED, DISTRIBUTED, DISCLOSED, ADAPTED, PERFORMED,
# DISPLAYED, COLLECTED, COMPILED, OR LINKED WITHOUT NOVELL'S PRIOR WRITTEN
# CONSENT.  USE OR EXPLOITATION OF THIS WORK WITHOUT AUTHORIZATION COULD SUBJECT
# THE PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY.
#
# NOVELL PROVIDES THE WORK "AS IS," WITHOUT ANY EXPRESS OR IMPLIED WARRANTY,
# INCLUDING WITHOUT THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE, AND NON-INFRINGEMENT. NOVELL, THE AUTHORS OF THE WORK, AND
# THE OWNERS OF COPYRIGHT IN THE WORK ARE NOT LIABLE FOR ANY CLAIM, DAMAGES, OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING
# FROM, OUT OF, OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS IN THE
# WORK.

require 'time'
require 'logger'
require 'rubygems'

# Add more ActiveSupport components here as needed. If the list grows too much,
# just put 'active_support/all' here (but let's avoid it if possible -- loading
# our enviroment is too slow already).
require 'active_support'
require 'active_support/core_ext/string/conversions'

begin
  require 'gelf' if OPTS.graylog2['enabled']
rescue NameError
end

module Common

  class Utils

    @@logger = nil

    # Convenience method for the rails default logger.
    def self.logger
      if !@@logger        
        if defined? Rails.logger
          @@logger = Rails.logger
        else
          @@logger = Logger.new STDERR
        end
      end
      @@logger
    end

    # Returns a randomly generated string, with a default length of 8 characters. 
    # A friendly salt does not include the numbers '0' and '1' since they are 
    # often confused by users with the letters 'O' and 'l'.
    def self.make_random_string(length=8, friendly=false)
      # Re-initialize seed to make things more random (srand + usec + pid).
      # Should reduce the odds of duplicates when multi-threading?
      srand(srand + Time.now.usec + $$) # TESTCASE: CWE-331 XXX tom: bad idea, it reduces entropy: http://thetoms-random-thoughts.blogspot.com/2008/06/ruby-and-openid-library.html
      chars = friendly ? 
        'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ23456789' :
        'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNOPQRSTUVWXYZ0123456789'
      random_string = ''
      length.downto(1) { random_string << chars[rand(chars.length - 1)] }
      random_string
    end

  end

end
