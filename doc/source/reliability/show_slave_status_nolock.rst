.. _show_slave_status_nolock:

=================================
 Lock-Free ``SHOW SLAVE STATUS``
=================================

The ``STOP SLAVE`` and ``SHOW SLAVE STATUS`` commands can conflict due to a global lock in the situation where one thread on a slave attempts to execute a ``STOP SLAVE`` command, while a second thread on the slave is already running a command that takes a long time to execute.

If a ``STOP SLAVE`` command is given in this situation, it will wait and not complete execution until the long-executing thread has completed its task. If another thread now executes a ``SHOW SLAVE STATUS`` command while the STOP SLAVE command is waiting to complete, the ``SHOW SLAVE STATUS`` command will not be able to execute while the ``STOP SLAVE`` command is waiting.

This features modifies the ``SHOW SLAVE STATUS`` syntax to allow: ::

  SHOW SLAVE STATUS NONBLOCKING

This will display the slave's status as if there were no lock, allowing the user to detect and understand the situation that is occurring.

.. note:: 

  The information given when ``NONBLOCKING`` is used may be slightly inconsistent with the actual situation while the lock is being held.

.. note::

   |Percona Server| originally used ``SHOW SLAVE STATUS NOLOCK`` syntax for this feature. As of :rn:`5.6.20-68.0` release, |Percona Server| implements ``SHOW SLAVE STATUS NONBLOCKING`` syntax, which comes from early |MySQL| 5.7. Current |MySQL| 5.7 does not have this syntax and regular ``SHOW SLAVE STATUS`` is non-blocking.

Status Variables
================

.. variable:: Com_show_slave_status_nolock

   :vartype: Numeric
   :varscope: Global/Session

The :variable:`Com_show_slave_status_nolock` statement counter variable indicates the number of times the statement ``SHOW SLAVE STATUS NOLOCK`` has been executed.

Version Specific Information
============================

  * :rn:`5.6.11-60.3`: Feature ported from |Percona Server| 5.5.

  * :rn:`5.6.20-68.0`: |Percona Server| implemented the ``NONBLOCKING`` syntax from |MySQL| 5.7 and deprecated the ``NOLOCK`` syntax.

  * :rn:`5.6.27-76.0`: ``SHOW SLAVE STATUS NOLOCK`` syntax in 5.6 has been undeprecated. Both ``SHOW SLAVE STATUS NOLOCK`` and ``SHOW SLAVE STATUS NONBLOCKING`` are now supported.
