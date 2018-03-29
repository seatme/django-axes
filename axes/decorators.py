from axes.models import AccessLog
from axes.settings import *
from axes.utils import is_already_locked, lockout_response, create_access_log, check_request, is_login_failed, is_ajax_login_failed, log_successful_attempt, log_decorated_call, get_ip
import axes

def watch_login(func):
    """
    Used to decorate the django.contrib.admin.site.login method.
    """

    # Don't decorate multiple times
    if func.__name__ == 'decorated_login':
        return func

    def decorated_login(request, *args, **kwargs):
        # share some useful information
        if func.__name__ != 'decorated_login' and VERBOSE:
            log_decorated_call(func, args, kwargs)

        # TODO: create a class to hold the attempts records and perform checks
        # with its methods? or just store attempts=get_user_attempts here and
        # pass it to the functions
        # also no need to keep accessing these:
        # ip = request.META.get('REMOTE_ADDR', '')
        # ua = request.META.get('HTTP_USER_AGENT', '<unknown>')
        # username = request.POST.get(USERNAME_FORM_FIELD, None)

        # if the request is currently under lockout, do not proceed to the
        # login function, go directly to lockout url, do not pass go, do not
        # collect messages about this login attempt
        if is_already_locked(request):
            return lockout_response(request, populate_login_form=True)

        # call the login function
        response = func(request, *args, **kwargs)

        if func.__name__ == 'decorated_login':
            # if we're dealing with this function itself, don't bother checking
            # for invalid login attempts.  I suppose there's a bunch of
            # recursion going on here that used to cause one failed login
            # attempt to generate 10+ failed access attempt records (with 3
            # failed attempts each supposedly)
            return response

        if request.method == 'POST':
            # see if the login was successful

            if request.is_ajax():
                login_unsuccessful = is_ajax_login_failed(response)
            else:
                login_unsuccessful = is_login_failed(response)

            # create a log of a login attempt
            create_access_log(request, login_unsuccessful)

            user_agent = request.META.get('HTTP_USER_AGENT', '<unknown>')[:255]
            http_accept = request.META.get('HTTP_ACCEPT', '<unknown>')[:1025]
            path_info = request.META.get('PATH_INFO', '<unknown>')[:255]
            if not DISABLE_ACCESS_LOG:
                username = request.POST.get(USERNAME_FORM_FIELD, None)
                ip_address = get_ip(request)

                if login_unsuccessful or not DISABLE_SUCCESS_ACCESS_LOG:
                    AccessLog.objects.create(
                        user_agent=user_agent,
                        ip_address=ip_address,
                        username=username,
                        http_accept=http_accept,
                        path_info=path_info,
                        trusted=not login_unsuccessful,
                    )
                if not login_unsuccessful and not DISABLE_SUCCESS_ACCESS_LOG:
                    log_successful_attempt(username, ip_address,
                                           user_agent, path_info)

            if check_request(request, login_unsuccessful):
                return response

            return lockout_response(request, populate_login_form=True)

        return response

    return decorated_login
