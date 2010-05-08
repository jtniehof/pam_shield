
AC_INIT(pam_shield, 0.9.2)
AC_CONFIG_HEADERS(config.h)
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_INSTALL
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_LN_S

AC_ARG_WITH([slibdir], AS_HELP_STRING([--with-slibdir=PATH],
	[Path to the super lib directory [[/lib]]]),
	[slibdir="$withval"], [slibdir="/lib"])
AC_SUBST(slibdir)

AC_CHECK_HEADER(gdbm.h, [],
	[AC_MSG_ERROR([You need to have gdbm-devel installed])])
AC_CHECK_HEADER(security/pam_modules.h,[have_pamheader="yes"],)
# Mac OS X 10.3 puts PAM headers in /usr/include/pam.
AC_CHECK_HEADER(pam/pam_modules.h,[have_pamheader="yes"],)
if test x"$have_pamheader" != x"yes"; then
	AC_MSG_ERROR(You are missing PAM headers)
fi

case "$host" in
(*-*-linux*)
	PAM_MODDIR="\$(slibdir)/security";
	;;
(*-*-darwin*)
	PAM_MODDIR="/usr/lib/pam";
	;;
(*)
	PAM_MODDIR="/usr/lib";
	;;
esac;
AC_SUBST(PAM_MODDIR)
AC_OUTPUT(Makefile)
