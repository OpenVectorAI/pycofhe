{{ fullname | escape | underline }}

.. currentmodule:: {{ module }}

.. autoclass:: {{ objname }}
   :members:
   :special-members:
   :private-members:
   :show-inheritance:
   :inherited-members:

   {% block methods %}
   .. automethod:: __init__

   {% if methods %}
   .. rubric:: Methods

   .. autosummary::
      {% for item in methods %}
         ~{{ name }}.{{ item }}
      {% endfor %}
   {% endif %}
   {% endblock %}

   {% block attributes %}
   {% if attributes %}
   .. rubric:: Attributes

   .. autosummary::
      {% for item in attributes %}
         ~{{ name }}.{{ item }}
      {% endfor %}
   {% endif %}
   {% endblock %}
