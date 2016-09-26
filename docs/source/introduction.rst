============
Introduction
============

The nmeta2 *(pronounced en-meta two)* project is founded on the belief that
innovation in networks requires a foundation layer of knowledge
about both the participants and their types of conversation.

Background
----------

Today, networks generally have only a limited view of participants
and conversation types

.. image:: images/nmeta2_concept.png

The goal of the nmeta2 project is to produce network metadata enriched with
participant identities and conversation types to provide a foundation for
innovation in networking.

The production of enriched network metadata requires policy-based control,
and ability to adapt to new purposes through extensibility.

Enriched network metadata has a number of uses, including classifying flows
for QoS, billing, traffic engineering, troubleshooting and security.

Nmeta2 is a research platform for traffic classification on Software Defined
Networking (SDN).  It runs on top of the Ryu SDN controller
(see: `<http://osrg.github.io/ryu/>`_).

Distributed System
------------------

Nmeta2 distributes the heavy-lifting work of traffic classification to
auxiliary devices, called a Data Plane Auxiliary Engines (DPAE), that
scale horizontally.

See separate repository for `DPAE <https://github.com/mattjhayes/nmeta2dpae>`_

Limitations
-----------
Nmeta2 code is under construction, so a number of features are not implemented
yet, or not finished.

Feature Enhancement Wishlist
----------------------------

See `Issues <https://github.com/mattjhayes/nmeta2/issues>`_ for list of
enhancements and bugs

Privacy Considerations
----------------------
Collecting network metadata brings with it ethical and legal considerations
around privacy. Please ensure that you have permission to monitor traffic
before deploying this software.

Disclaimer
----------

This code carries no warrantee whatsoever. Use at your own risk.

How to Contribute
-----------------

Code contributions and suggestions are welcome. Enhancement or bug fixes
can be raised as issues through GitHub.

Please get in touch if you want to be added as a contributor to the project:

Email: `Nmeta Maintainer <mailto:nmeta-maintainer@outlook.com>`_
