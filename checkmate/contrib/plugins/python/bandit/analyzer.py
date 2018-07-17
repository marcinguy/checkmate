# -*- coding: utf-8 -*-

from __future__ import unicode_literals
from __future__ import absolute_import

from checkmate.lib.analysis.base import BaseAnalyzer

import logging
import os
import tempfile
import json
import pprint
import subprocess

logger = logging.getLogger(__name__)

class BanditAnalyzer(BaseAnalyzer):

    def __init__(self, *args, **kwargs):
        super(BanditAnalyzer, self).__init__(*args, **kwargs)
        try:
            result = subprocess.check_output(["bandit","--version"])
        except subprocess.CalledProcessError:
            logger.error("Cannot initialize Bandit analyzer: Executable is missing, please install it.")
            raise

    def summarize(self,items):
        pass

    def analyze(self,file_revision):
        issues = []
        f = tempfile.NamedTemporaryFile(delete = False)
        try:
            with f:
                f.write(file_revision.get_file_content())
            try:
                result = subprocess.check_output(["bandit",
                                                  f.name,
                                                  "-f",
                                                  "json"])
            except subprocess.CalledProcessError as e:
                if e.returncode == 2:
                    result = e.output
                elif e.returncode == 1:
                    result = e.output
                    pass
		else:
                    raise
            json_result = json.loads(result)
            
            for issue in json_result['results']:

                location = (((issue['line_number'],None),
                              (issue['line_number'],None)),)



                issues.append({
                    'code' : issue['code'],
                    'data' : issue['issue_text'],
                    'fingerprint' : self.get_fingerprint_from_code(file_revision,location, extra_data=issue['issue_text'])
                    })

        finally:
            os.unlink(f.name)
        return {'issues' : issues}
