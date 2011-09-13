# 2011/09/12: slms/webapp/lib/gpg_key.rb
#
#  Copyright (c) 2010 Novell, Inc.
#  All Rights Reserved.
#
#  This library is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License as
#  published by the Free Software Foundation; version 2.1 of the license.
#
#  This library is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.   See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with this library; if not, contact Novell, Inc.
#
#  To contact Novell about this file by physical or electronic mail,
#  you may find current contact information at www.novell.com


# Class for checking GPG key expiration
class GpgKey
  attr_reader :expiration, :key_id, :path

  GNUPG_DIR = '.gnupg'
  GNUPG_SECRET_KEYRING = 'secring.gpg'
  GNUPG_BINARY = '/usr/bin/gpg'

  def self.default_key_id
    key_id = Slms::Config.value_for('Updates', 'signing_key_id')
    raise "There is no default GPG key ID in SLMS configuration" unless key_id.present?
    return key_id
  end

  # Creates a new GpgKey object
  # @param (#to_s) path to SLMS GPG directory (optional, by default taken from config)
  def initialize path = nil
    path = File.join(Slms::Config.value_for_with_default('SLMS', 'slms_homedir'), GNUPG_DIR) if path.blank?
    raise Errno::ENOENT.new path unless File.directory? path

    @path = path
  end

  private

  # Returns a mail-formatted key export
  def export_key key_id
    gpg = ExternalProgram.new(GNUPG_BINARY, ["--homedir", @path, "--armor", "--export", '--', key_id]) # TESTCASE: CWE-78, CWE-88
    gpg.run

    raise Exception.new _("Cannot export GPG key ID %s from %s directory: %s", key_id, @path, gpg.stderr) unless gpg.exit_value.zero?

    gpg.stdout.to_s
  end
end
