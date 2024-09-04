#!/usr/bin/python3
import sys
import re
import os
import fcntl
import fnmatch
import string
import shutil
import hashlib
import base64
import logging
import configparser
import traceback
import google
from collections import OrderedDict
from collections.abc import Mapping
from time import time
import multiprocessing.dummy as Thread
from multiprocessing.dummy import Pool as ThreadPool
# Import the Google Cloud client library
from google.cloud import storage
#
from retrying import retry
import pyrax
# ugly fix to issue described here: https://community.rackspace.com/developers/f/7/t/5783
import requests
requests.packages.urllib3.disable_warnings()    # pylint: disable=no-member
# end ugly


class LockFile(object):
    """lockfile creation class"""
    def __init__(self, lockpath):
        self.lockpath = lockpath
        self._lockfile = None
        LOG.debug('LockFile init: lockpath=%s _lockfile=%s', self.lockpath, self._lockfile)
    def lock(self):
        """Locks the lockfile."""
        if self._lockfile:
            LOG.debug('LockFile.lock() has self._lockfile so return.')
            return
        LOG.debug('LockFile.lock() does not have self._lockfile.')
        LOG.debug('LockFile.lock() attempting open() for append+ type(self._lockfile=%s)',
                  type(self._lockfile))
        fpath = open(self.lockpath, "a+")
        LOG.debug('LockFile.lock() seek to 0 / beginning of file')
        fpath.seek(0)
        LOG.debug('LockFile.lock() fpath.readline().rstrip()')
        LOG.debug(fpath.readline().rstrip())
        LOG.debug('LockFile.lock() fpath.read()')
        LOG.debug(fpath.read())
        LOG.debug('(end of read)')
        try:
            LOG.debug('fpath.fileno()=%s [int file descriptor]', fpath.fileno())
            # file control lock(file descriptor
            # acquire exclusive lock | avoid blocking on lock acquisition)
            fcntl.lockf(fpath.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)
        except IOError:
            LOG.error('%s is currently running with pid %s.  Skipping this round.'
                      , os.path.basename(sys.argv[0]), fpath.readline().rstrip())
            sys.exit(1)
        else:
            fpath.write("%s\n" % os.getpid())
            fpath.flush()
            self._lockfile = fpath
            LOG.debug('Wrote PID to lockfile, and now self._lockfile=%s type=%s',
                      self._lockfile, type(self._lockfile))
    def unlock(self):
        """Unlocks/removes the lockfile."""
        if self._lockfile:
            remove(self.lockpath)
            self._lockfile.close()
            self._lockfile = None
    def __del__(self):
        self.unlock()


def walk(path):
    """Walk our backup folder."""
    include = ['*hourly*', '*daily*', '*monthly*']
    include_file_filter = re.compile(
        r'|'.join([fnmatch.translate(matcher) for matcher in include]))
    for _path, _subdirs, files in os.walk(path):
        for filename in files:
            if include_file_filter.match(filename):
                yield filename

def get_trace():
    """easy trace function."""
    text = ' '
    trace_list = traceback.format_exception(sys.exc_info()[0],
                                            sys.exc_info()[1],
                                            sys.exc_info()[2])
    text = "".join(trace_list)
    return text


def get_cloudfile_object(creds):
    """retrieve cloudfile object."""
    region, itype, ruser, apikey = creds
    try:
        pyrax.set_default_region(region)
        pyrax.set_setting("identity_type", itype)
        pyrax.set_credentials(ruser, apikey)
        cfile = pyrax.cloudfiles
    except (Exception):
        LOG.error('Unable To Connect To CloudFile')
        LOG.error(get_trace())
        sys.exit(1)
    return cfile

def get_md5sum_from_fname(fname):
    """Regex to parse out the md5sum from the filename."""
    try:
        # Attempt to match the regex pattern to the filename
        match = re.match(r'^.*\.(.*)-.*$', fname)
        if match:
            md5_string = match.group(1)
        else:
            raise AttributeError("Regex match not found")

    # Catch filenames that do not parse as expected
    except AttributeError:
        LOG.error('Unable to parse md5sum from filename: %s', fname)
        md5_string = 'UNKNOWN'
    LOG.debug('get_md5sum_from_fname() fname=%s result=%s', fname, md5_string)
    return md5_string


def get_md5sum(fname):
    """generate md5sum using pyrax.utils."""
    try:
        cksum = pyrax.utils.get_checksum(fname)
        LOG.debug('get_md5sum()            fname=%s result=%s', fname, cksum)
    except (Exception):
        LOG.error('Unable To Generate Md5Sum')
        LOG.error(get_trace())
        sys.exit(1)
    return cksum


def get_md5base64(fname):
    """Return base64-encoded md5sum of a file."""
    hasher = hashlib.md5()

    # Open the file in binary mode
    with open(fname, 'rb') as fobj:
        for chunk in iter(lambda: fobj.read(4096), b""):
            hasher.update(chunk)

    # Base64 encode the MD5 digest
    md5base64 = base64.b64encode(hasher.digest()).decode('utf-8')
    LOG.debug('get_md5base64()         fname=%s result=%s', fname, md5base64)
    return md5base64


def get_open_file_md5(fname, blocksize=122880):
    """Return md5sum for open file."""
    hasher = hashlib.md5()
    with open(os.path.join(fname), "rb") as fhash:
        while True:
            buf = fhash.read(blocksize)
            if not buf:
                break
            hasher.update(buf)
    return hasher.hexdigest()


def retry_if_result_none(result):
    """Return True if we should retry (in this case when result is None), False otherwise"""
    return result is None


@retry(retry_on_result=retry_if_result_none, wait_exponential_multiplier=5000, \
       wait_exponential_max=6000, stop_max_delay=60000)
def md5sum_recheck(archive):
    """if our check fails we assume the file could be in mid scp stream.  check md5sum
        status over 1 minute and if we are still failing we can throw the file to failure."""
    LOG.debug('md5sum_recheck() [%s] waiting on: %s %s:%s',
              Thread.current_process().name,
              archive['archive_name'],
              UPLOAD_STATUS[archive['file_path']]['md5sum'],
              archive['md5sum_filename'])
    open_md5 = get_open_file_md5(archive['file_path'])
    LOG.debug('md5sum_recheck() [%s] open_md5=%s md5sum_filename=%s',
              Thread.current_process().name, open_md5, archive['md5sum_filename'])
    if open_md5 == archive['md5sum_filename']:
        LOG.info('md5sum_recheck() [%s] md5sum matches now for %s!',
                 Thread.current_process().name, archive['archive_name'])
        # update results and file metadata
        UPLOAD_STATUS[archive['file_path']]['md5base64'] = get_md5base64(archive['file_path'])
        UPLOAD_STATUS[archive['file_path']]['md5sum_ok'] = True
        UPLOAD_STATUS[archive['file_path']]['md5sum'] = open_md5
        return archive
    # if we hit this, the md5sum didn't match
    LOG.debug("md5sum_recheck() [%s] md5sum still doesn't match for %s",
              Thread.current_process().name, archive['archive_name'])
    return None     # retry if the result is None


def move_archive(src, dest):
    """file mover."""
    short_name = get_short_name(src)
    try:
	# if our file already exists in the dest folder
	# lets remove it before moving our file
        dest_file = dest + os.sep + short_name
        if os.path.exists(dest_file):
            os.remove(dest_file)
        shutil.move(src, dest)
    except (OSError):
        LOG.error('Failed Moving Archive ( %s )', src)
        LOG.error(get_trace())
    LOG.debug('Archive: %s Successfully Moved To: %s', short_name, dest)


def get_folder_type(archive):
    """extract the folder type from the path."""
    try:
        sep = archive.split('-')
        folder_type = sep[-1]
    except:
        folder_type = archive
    return folder_type


def get_short_name(archive):
    """extract the archive name from full path."""
    try:
        sep = archive.split(os.sep)
        short_name = sep[-1]
    except:
        short_name = archive
    return short_name


@retry(stop_max_attempt_number=2, wait_exponential_multiplier=1000, wait_exponential_max=10000)
def upload_to_rackspace(archive):
    """upload archive and retry if our md5sum verification fails."""
    LOG.debug('upload_to_rackspace() [%s] START', Thread.current_process().name)
    LOG.debug('upload_to_rackspace() [%s] Uploading %s (cksum/etag=%s)',
              Thread.current_process().name,
              archive['dest_name'],
              UPLOAD_STATUS[archive['file_path']]['md5sum'])
    try:
        upobj = CLOUD_FILES.upload_file(RACKSPACE_CONTAINER, archive['file_path'],
                                        archive['dest_name'],
                                        etag=UPLOAD_STATUS[archive['file_path']]['md5sum'])
    except (Exception):
        LOG.error('upload_to_rackspace() Failed Uploading Archive to CloudFile')
        LOG.error(get_trace())
    finally:
        # debug: uncomment to force md5sum failure
        #upobj.etag = 'FORCEFAIL'
        # rollback if md5sum changed during data stream
        if UPLOAD_STATUS[archive['file_path']]['md5sum'] != upobj.etag:
            LOG.error('md5sum check failed for %s', archive['archive_name'])
            LOG.debug('local: %s | rackspace: %s',
                      UPLOAD_STATUS[archive['file_path']]['md5sum'], upobj.etag)
            up_result = delete_remote_object(archive['dest_name'])
            LOG.info('Removal From CloudFile: %s - %s', archive['dest_name'], up_result)
        else:
            LOG.info('Successful upload of %s to rackspace:%s',
                     archive['file_path'], archive['dest_name'])
            UPLOAD_STATUS[archive['file_path']]['good_upload'].append('rackspace')
    LOG.debug('upload_to_rackspace() [%s] END', Thread.current_process().name)


def remove(path):
    """remove file."""
    LOG.debug("Removing (%s)", path)
    try:
        os.remove(path)
    except (Exception):
        LOG.error('Failed To Remove Archive ( %s )', path)
        LOG.error(get_trace())


def delete_remote_object(oname):
    """delete our remote archive."""
    try:
        CONT.delete_object(oname)
    except (Exception):
        LOG.error('Failed Deleting Remote Object ( %s )', oname)
        LOG.error(get_trace())
        return 'FAIL'
    return 'OK'


def get_folder_size(start_path):
    """size of backup_path in bytes."""
    total_size = 0
    filenames = walk(start_path)
    for fname in filenames:
        full_path = os.path.join(start_path, fname)
        total_size += os.path.getsize(full_path)
    return total_size


def format_size(num, suffix='B'):
    """bytes to N formatter."""
    for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


def check_dir_state(path):
    """checks our backup directory for data
        returns True if directory is empty."""
    return bool(os.listdir(path) == [])


def configreader(section):
    """Reads in configuration file to a dict."""
    dict1 = {}
    options = OSSCONF.options(section)
    for option in options:
        try:
            dict1[option] = OSSCONF.get(section, option)
            if dict1[option] == -1:
                LOG.debug("skip: %s", option)
        except:
            LOG.error('exception on %s!', option)
            dict1[option] = None
    return dict1


@retry(stop_max_attempt_number=2, wait_exponential_multiplier=1000, wait_exponential_max=10000)
def upload_to_google(archive):
    """Uploads a file to the bucket."""
    LOG.debug('upload_to_google() [%s] START', Thread.current_process().name)
    LOG.debug('upload_to_google() [%s] Uploading %s (md5_hash/md5base64=%s)',
              Thread.current_process().name,
              archive['dest_name'],
              UPLOAD_STATUS[archive['file_path']]['md5base64'])
    try:
        # Reusing the storage.Client() object instead of instantiating a new one in this function
        # results in fewer HTTP GET requests.
        blob = GOOGLE_BUCKET.blob(archive['dest_name'])
        blob.upload_from_filename(archive['file_path'])
        google_md5_hash = blob.md5_hash
        if UPLOAD_STATUS[archive['file_path']]['md5base64'] != google_md5_hash:
            LOG.error('md5base64 check failed for %s', archive['archive_name'])
            LOG.debug('local: %s | google: %s',
                      UPLOAD_STATUS[archive['file_path']]['md5base64'], google_md5_hash)
            res = delete_from_google(archive['dest_name'])
            LOG.info('Removal From Google Storage: %s - %s', archive['dest_name'], res)
            LOG.debug('upload_to_google() [%s] END', Thread.current_process().name)
        else:
            LOG.info('Successful upload of %s to google:%s',
                     archive['file_path'], archive['dest_name'])
            UPLOAD_STATUS[archive['file_path']]['good_upload'].append('google')
    except google.api_core.exceptions.Forbidden:
        LOG.error('Sorry, looks like you do not have permission for this!')
    LOG.debug('upload_to_google() [%s] END', Thread.current_process().name)


def delete_from_google(blob_name):
    """Deletes a file from the bucket."""
    try:
        blob = GOOGLE_BUCKET.blob(blob_name)
        blob.delete()
        LOG.debug('blob %s deleted.', blob_name)
    except google.api_core.exceptions.Forbidden:
        LOG.error('Sorry, looks like you do not have permission for this!')
        return 'FAIL'
    except google.api_core.exceptions.NotFound:
        LOG.error('Could not find file in storage bucket!')
        return 'FAIL'
    return 'OK'

# start
if __name__ == '__main__':
    TIMER = time()
    # list of supported storage targets the configuration can use
    SUPPORTED_STORAGE_PROVIDERS = ['google', 'rackspace']

    # The maximum number of attempts to try to upload a file
    # (could retry due to md5sum mismatch, for example)
    # Added to work around exception catching during upload that could cause all other uploads
    # to abandon.
    MAX_ATTEMPTS = 2

    # config parsing goodness
    ENVIRONMENT_TYPE = 'prod'
    CONFIG_PATH = 'conf/cloud_backup.conf'
    OSSCONF = configparser.ConfigParser()
    OSSCONF.read(CONFIG_PATH)
    # obtain the storage targets (comma-separated)
    STORAGE_PROVIDERS = configreader(ENVIRONMENT_TYPE)['storage_providers'].split(',')
    # get rid of any whitespace on elements
    STORAGE_PROVIDERS = [x.strip() for x in STORAGE_PROVIDERS]
    # get rid of any duplicates
    STORAGE_PROVIDERS = OrderedDict((x, True) for x in STORAGE_PROVIDERS).keys()
    # get rid of empty elements
    STORAGE_PROVIDERS = [x for x in STORAGE_PROVIDERS if x]
    NUM_STORAGE_PROVIDERS = len(STORAGE_PROVIDERS)
    for x in STORAGE_PROVIDERS:
        if x not in SUPPORTED_STORAGE_PROVIDERS:
            print("Unsupported storage provider: %s  Supported providers: %s" %
                  (x, SUPPORTED_STORAGE_PROVIDERS))
            sys.exit(2)
    if NUM_STORAGE_PROVIDERS < 1:
        print ("No storage providers found from configuration file: %s." % CONFIG_PATH)
        sys.exit(2)

    # read in relevant storage target config
    if 'google' in STORAGE_PROVIDERS:
        # google storage bucket name
        GOOGLE_BUCKET_NAME = configreader(ENVIRONMENT_TYPE)['google_bucket']
    if 'rackspace' in STORAGE_PROVIDERS:
        # rackspace region
        RACKSPACE_REGION = configreader(ENVIRONMENT_TYPE)['rackspace_region']
        # rackspace identity
        RACKSPACE_IDENTITY_TYPE = configreader(ENVIRONMENT_TYPE)['rackspace_identity_type']
        # rackspace user
        RACKSPACE_USER = configreader(ENVIRONMENT_TYPE)['rackspace_user']
        # rackspace api key
        RACKSPACE_API_KEY = configreader(ENVIRONMENT_TYPE)['rackspace_api_key']

    # how many workers we spawn
    WORKER_COUNT = configreader(ENVIRONMENT_TYPE)['worker_count']
    #print("WORKER_COUNT=%s type(WORKER_COUNT)=%s" % (WORKER_COUNT, type(WORKER_COUNT)))
    # location for ready to be processed backups
    BACKUP_LOCATION = configreader(ENVIRONMENT_TYPE)['backup_location']
    # location for failed transfers
    FAILURE_LOCATION = configreader(ENVIRONMENT_TYPE)['failure_location']
    # Lock file path
    LOCK_FILE = configreader(ENVIRONMENT_TYPE)['lock_path']
    # log file location
    LOG_LOCATION = configreader(ENVIRONMENT_TYPE)['log_location']
    # cloudfile container name
    RACKSPACE_CONTAINER = configreader(ENVIRONMENT_TYPE)['rackspace_bucket']
    # change requests logging to less chatty, enable for more verbose http request info
    logging.getLogger('requests').setLevel(logging.WARNING)
    # initialize better logging
    LOG = logging.getLogger()
    LOG.setLevel(logging.DEBUG)
    # create file handler which logs error messages
    LOG_HANDLER = logging.FileHandler(LOG_LOCATION)
    LOG_HANDLER.setLevel(logging.DEBUG)
    # create console handler with a higher log level
    CONSOLE_HANDLER = logging.StreamHandler()
    CONSOLE_HANDLER.setLevel(logging.DEBUG)
    # create formatter and add it to the handlers
    FORMATTER = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    LOG_HANDLER.setFormatter(FORMATTER)
    CONSOLE_HANDLER.setFormatter(FORMATTER)
    # add the handlers to the logger
    LOG.addHandler(LOG_HANDLER)
    LOG.addHandler(CONSOLE_HANDLER)
    LOG.debug('---------START-----------')
    # make sure we have failure directory
    if not os.path.exists(FAILURE_LOCATION):
        os.mkdir(FAILURE_LOCATION)
        LOG.error('Missing FAILURE_LOCATION directory: %s', FAILURE_LOCATION)
        sys.exit(2)

    # establish lock
    LOCK = LockFile(LOCK_FILE)
    # start script only once if backup path contains data
    EMPTY = check_dir_state(BACKUP_LOCATION)
    if EMPTY is False:
        LOCK.lock()
        LOG.info('storage provider(s): %s', STORAGE_PROVIDERS)
        # generate a list of all backups in our backup path
        LOG.info('Calculating Backups to Process...')
        BACKUP_PATHS = [BACKUP_LOCATION + os.sep + x for x in walk(BACKUP_LOCATION)]
        print(BACKUP_LOCATION)
        LOG.debug('(%s) BACKUP_PATHS: %s', len(BACKUP_PATHS), BACKUP_PATHS)

        ALL_BACKUPS = []
        UPLOAD_STATUS = {}
        for backup_file in BACKUP_PATHS:
            # build file metadata
            aname = get_short_name(backup_file)
            ftype = get_folder_type(backup_file)
            dest_name = "%s/%s" % (ftype, get_short_name(backup_file))
            md5sum_ok = True
            # the backup file is expected to have it's md5sum encoded in the filename.
            md5sum_filename = get_md5sum_from_fname(backup_file)
            # calculate md5 values of the file data
            md5sum_filedata = get_md5sum(backup_file)
            md5base64_filedata = get_md5base64(backup_file)
            # we expect them to match for the file to be 'good to go'
            if md5sum_filename != md5sum_filedata:
                md5sum_ok = False
            UPLOAD_STATUS[backup_file] = {'good_upload': [],
                                          'md5sum_ok': md5sum_ok,
                                          'md5sum': md5sum_filedata,
                                          'md5base64': md5base64_filedata}
            file_metadata = {'file_path': backup_file, 'archive_name': aname,
                             'dest_name': dest_name, 'folder_type': ftype,
                             'md5sum_filename': md5sum_filename}
            ALL_BACKUPS.append(file_metadata)
        LOG.debug('(%s) ALL_BACKUPS  : %s', len(ALL_BACKUPS), ALL_BACKUPS)
        LOG.debug('(%s) UPLOAD_STATUS: %s', len(UPLOAD_STATUS), UPLOAD_STATUS)

	# determine size of our backups
        BACKUP_SIZE = format_size(get_folder_size(BACKUP_LOCATION))
        LOG.debug('BACKUP_SIZE: %s', BACKUP_SIZE)

        # connect to storage provider(s)
        if 'rackspace' in STORAGE_PROVIDERS:
            LOG.debug('Connecting To Rackspace...')
            CREDENTIALS = (RACKSPACE_REGION, RACKSPACE_IDENTITY_TYPE,
                           RACKSPACE_USER, RACKSPACE_API_KEY)
            LOG.debug('(rackspace) CREDENTIALS: %s', str(CREDENTIALS))
            CLOUD_FILES = get_cloudfile_object(CREDENTIALS)
            ALL_CONT = CLOUD_FILES.list_containers()
            LOG.debug('(rackspace) ALL_CONT: %s', ALL_CONT)
            RESPONSE = ('(rackspace) Could Not Find ( %s ) In Our Container List, Creating...',
                        RACKSPACE_CONTAINER)
            if RACKSPACE_CONTAINER in ALL_CONT:
                RESPONSE = ('(rackspace) Found ( %s ) In Our Container List, Using...',
                            RACKSPACE_CONTAINER)
            LOG.debug(RESPONSE)
            # create_container() will create if does not exist
            # or return the container object if exists
            CONT = CLOUD_FILES.create_container(RACKSPACE_CONTAINER)
        if 'google' in STORAGE_PROVIDERS:
            LOG.debug('Connecting to Google...')
            # Instantiates a client
            GOOGLE_STORAGE_CLIENT = storage.Client()
            # try to look for bucket.
            # we will reuse tbe GOOGLE_BUCKET where possible to reduce connections
            try:
                LOG.debug('(google) Try to find bucket (%s)', GOOGLE_BUCKET_NAME)
                GOOGLE_BUCKET = GOOGLE_STORAGE_CLIENT.get_bucket(GOOGLE_BUCKET_NAME)
                LOG.debug('(google) Bucket found: name=%s storage_class=%s time_created=%s',
                          GOOGLE_BUCKET.name, GOOGLE_BUCKET.storage_class,
                          GOOGLE_BUCKET.time_created)
            except google.api_core.exceptions.NotFound:
                LOG.warning('(google) Sorry, bucket %s does not exist!', GOOGLE_BUCKET_NAME)
                GOOGLE_BUCKET = None
            except google.api_core.exceptions.Forbidden:
                LOG.error('(google) Sorry, looks like you do not have permission for this!')
                GOOGLE_BUCKET = None
            # if bucket not found, try and create it, setting the storage_class to 'COLDLINE'
            if not GOOGLE_BUCKET:
                try:
                    LOG.info('(google) Try to create new bucket (%s)', GOOGLE_BUCKET_NAME)
                    GOOGLE_BUCKET = GOOGLE_STORAGE_CLIENT.bucket(GOOGLE_BUCKET_NAME)
                    GOOGLE_BUCKET.storage_class = 'COLDLINE'
                    GOOGLE_BUCKET.create()
                    LOG.info('(google) Bucket %s created, storage_class=%s',
                             GOOGLE_BUCKET.name, GOOGLE_BUCKET.storage_class)
                # without a usable bucket, we can't copy files to this provider
                except google.api_core.exceptions.Forbidden:
                    LOG.error('(google) Permission -  could not create new bucket: %s',
                              GOOGLE_BUCKET_NAME)
                    sys.exit(2)
                except google.api_core.exceptions.BadRequest:
                    LOG.error('(google) Bad Request - check format of bucket name (%s)',
                              GOOGLE_BUCKET_NAME)
                    sys.exit(2)
                except google.api_core.exceptions.Conflict:
                    LOG.error('(google) Name Conflict - try a different bucket name (tried: %s)',
                              GOOGLE_BUCKET_NAME)
                    sys.exit(2)

        if ALL_BACKUPS:
            # process all archives
            LOG.info('(process ALL archives)')
            for attempt in range(1, MAX_ATTEMPTS + 1):
                LOG.info('attempt=%s/%s (recheck any failed md5sums)', attempt, MAX_ATTEMPTS)
                # handle files that failed our initial md5sum check
                # we do this before the upload to provider so that files that now pass the md5sum
                # check can be included in the uploads.
                BACKUPS_TO_MD5SUM_RECHECK = []
                for backup in ALL_BACKUPS:
                    # only match backup files that have don't have a good md5sum check yet
                    # the filename must have the proper naming convention though.
                    if not (UPLOAD_STATUS[backup['file_path']]['md5sum_ok']) and \
                           (backup['md5sum_filename'] != 'UNKNOWN'):
                        BACKUPS_TO_MD5SUM_RECHECK.append([f for f in ALL_BACKUPS if \
                                                         f['file_path'] == backup['file_path']][0])
                LOG.debug('(%s) BACKUPS_TO_MD5SUM_RECHECK: %s',
                          len(BACKUPS_TO_MD5SUM_RECHECK), BACKUPS_TO_MD5SUM_RECHECK)
                RESPONSE = None
                try:
                    POOL = ThreadPool(int(WORKER_COUNT))
                    POOL.map(md5sum_recheck, BACKUPS_TO_MD5SUM_RECHECK)
                    POOL.close()
                    POOL.join()
                except:
                    LOG.error('Not all files passed md5sum_recheck()!')

                # handle uploads
                for provider in STORAGE_PROVIDERS:
                    LOG.info('attempt=%s/%s provider=%s', attempt, MAX_ATTEMPTS, provider)
                    # handle uploads to rackspace
                    if provider == 'rackspace':
                        BACKUPS_TO_USE = []
                        for backup in ALL_BACKUPS:
                            # only attempt backup files that have passed md5sum and
                            # haven't already been uploaded to this provider
                            if (UPLOAD_STATUS[backup['file_path']]['md5sum_ok']) and \
                               (provider not in UPLOAD_STATUS[backup['file_path']]['good_upload']):
                                BACKUPS_TO_USE.append([f for f in ALL_BACKUPS if \
                                                      f['file_path'] == backup['file_path']][0])
                        LOG.debug('(%s) BACKUPS_TO_USE: %s', len(BACKUPS_TO_USE), BACKUPS_TO_USE)
                        try:
                            # pass our archives to our threading module for processing
                            POOL = ThreadPool(int(WORKER_COUNT))
                            POOL.map(upload_to_rackspace, BACKUPS_TO_USE)
                            POOL.close()
                            POOL.join()
                        except:
                            LOG.error('Unexpected error ocurred during upload to rackspace!')
                    # handle uploads to google
                    if provider == 'google':
                        BACKUPS_TO_USE = []
                        for backup in ALL_BACKUPS:
                            # only attempt backup files that have passed md5sum and
                            # haven't already been uploaded to this provider
                            if (UPLOAD_STATUS[backup['file_path']]['md5sum_ok']) and \
                               (provider not in UPLOAD_STATUS[backup['file_path']]['good_upload']):
                                BACKUPS_TO_USE.append([f for f in ALL_BACKUPS if \
                                                      f['file_path'] == backup['file_path']][0])
                        LOG.debug('(%s) BACKUPS_TO_USE: %s', len(BACKUPS_TO_USE), BACKUPS_TO_USE)
                        try:
                            # pass our archives to our threading module for processing
                            POOL = ThreadPool(int(WORKER_COUNT))
                            POOL.map(upload_to_google, BACKUPS_TO_USE)
                            POOL.close()
                            POOL.join()
                        except:
                            LOG.error('Unexpected error ocurred during upload to google!')
        LOG.debug('MAX_ATTEMPTS (%s) reached.', MAX_ATTEMPTS)
        LOG.debug('UPLOAD_STATUS: %s', UPLOAD_STATUS)
        # iterate through UPLOAD_STATUS to log results
        for backup, meta in UPLOAD_STATUS.iteritems():
            LOG.debug("File: %s md5sum_ok: %s md5sum: %s md5base64: %s good_upload: %s",
                      backup, meta['md5sum_ok'], meta['md5sum'],
                      meta['md5base64'], meta['good_upload'])
            good_uploads = len(meta['good_upload'])
            if good_uploads == NUM_STORAGE_PROVIDERS:
                LOG.info("File: %s was successfully uploaded to all storage provider(s)", backup)
                remove(backup)
            else:
                LOG.warn("File: %s was uploaded to %s/%s storage provider(s) (uploaded to: %s)",
                         backup, good_uploads, NUM_STORAGE_PROVIDERS, meta['good_upload'])
                move_archive(backup, FAILURE_LOCATION)

        LOG.info('Took %s seconds to process %s archives (%s) with %s worker(s)',
                 time() - TIMER, len(ALL_BACKUPS), BACKUP_SIZE, WORKER_COUNT)
	# release our lock
        LOCK.unlock()
#### END ####
