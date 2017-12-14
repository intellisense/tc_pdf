try:
    from urlparse import urlparse
except ImportError:
    from urllib.parse import urlparse


class PDF(object):

    def __init__(self, context):
        """
        :param context: an instance of `CommunityContext`
        """

        self.context = context

    def get(self, path):
        """
        Get from storage
        :param path: source path
        :return: None or binary content
        """
        return self.context.modules.storage.get(path)

    def put(self, path, bytes_data):
        """
        Save `bytes_data` to the specified `path`
        :param path: source path
        :param bytes_data: binary content
        :return: path or new path if collision occur
        """
        return self.context.modules.storage.put(path, bytes_data)

    def url_parts(self, url):
        """
        Utility method which checks if `url` has valid protocol and return its parts along with the fixed url
        :param url: HTTP url of resource
        :return: tuple: ParseResult instance and url
        """
        url = self.fix_url(url)
        return urlparse(url), url

    @staticmethod
    def fix_url(url):
        """
        Check if url has valid protocol if not set `http`
        :param url: HTTP url of resource
        :return: url with protocol
        """
        if not url.lower().startswith('http://') and not url.lower().startswith('https://'):
            url = u'http://' + url
        return url
