<%inherit file='xml_base.mako' />

<section name="dialplan" description="blablu">
  <context name="default">
    <extension name="${ extension }">
      <condition field="destination_number" expression="^${ extension }$">
        % for sequence in route.sequences:
          <action application="${ sequence.action.application_catalog.command }" data="${ sequence.action.application_data }"/>
        % endfor
      </condition>
    </extension>
  </context>
</section>
