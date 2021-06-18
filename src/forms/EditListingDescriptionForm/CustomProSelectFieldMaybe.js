import React from 'react';
import { FieldSelect } from '../../components';

import css from './EditListingDescriptionForm.module.css';

const CustomProSelectFieldMaybe = props => {
  const { name, id, proOptions, intl } = props;
  const proLabel = intl.formatMessage({
    id: 'EditListingDescriptionForm.proLabel',
  });

  return proOptions ? (
    <FieldSelect className={css.pro} name={name} id={id} label={proLabel}>
      {proOptions.map(c => (
        <option key={c.key} value={c.key}>
          {c.label}
        </option>
      ))}
    </FieldSelect>
  ) : null;
};

export default CustomProSelectFieldMaybe;
