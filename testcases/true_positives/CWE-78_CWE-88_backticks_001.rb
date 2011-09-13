# 2011/09/12: common/lib/common/start_server.rb
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

require 'optparse'
require "#{File.dirname(__FILE__)}/options"
require 'fileutils'

module Common

# Generic helper class for starting Rails app servers (ui-server, . 
# Allows additional command line arguments to be passed into the server during
# server startup.
# Please see 'ui-server/script/start_server' and 'ui-server/config/environment.rb'
# for usage examples.
class StartServer

  # Initializes the StartServer object.
  def initialize script_file, extra_args={}, notes=nil
    @script_file = File.expand_path script_file
    @defaults = Options.read_options(:environment => 'default',
                                     :verbose     => 'silent')
    parse_cmd_line_args(extra_args, notes)
    @defaults.update @cmd_line_args
    clean_up
  end

  # Runs the specified command. Also redirects the command's stdout to stderr
  # so that it can be seen in the running terminal.
  def run cmd
    cmd += ' 1>&2'
    vputs "Executing '#{cmd}'"
    `#{cmd}` # TESTCASE: CWE78, CWE-88
  end
end
