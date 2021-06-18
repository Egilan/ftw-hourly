import React from 'react';
import { FormattedMessage } from '../../util/reactIntl';
import { InlineTextButton } from '../../components';

import css from './ListingPage.module.css';

const getProInfo = (proOptions, key) => {
  return proOptions.find(c => c.key === key);
};

const SectionHeading = props => {
  const {
    richTitle,
    listingPro,
    proOptions,
    showContactUser,
    onContactUser,
  } = props;

  const pro = getProInfo(proOptions, listingPro);
  const showPro = pro && !pro.hideFromListingInfo;
  return (
    <div className={css.sectionHeading}>
      <div className={css.heading}>
        <h1 className={css.title}>{richTitle}</h1>
        <div className={css.author}>
          {showPro ? <span>{pro.label}</span> : null}
          {showContactUser ? (
            <span className={css.contactWrapper}>
              {showPro ? <span className={css.separator}>•</span> : null}
              <InlineTextButton rootClassName={css.contactLink} onClick={onContactUser} enforcePagePreloadFor="SignupPage">
                <FormattedMessage id="ListingPage.contactUser" />
              </InlineTextButton>
            </span>
          ) : null}
        </div>
      </div>
    </div>
  );
};

export default SectionHeading;
