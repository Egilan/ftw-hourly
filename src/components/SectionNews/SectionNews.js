import React from 'react';
import { bool, string } from 'prop-types';
import classNames from 'classnames';
import { FormattedMessage } from '../../util/reactIntl';
import { propTypes } from '../../util/types';
import { OwnListingLink } from '..';

import css from './SectionNews.module.css';


import { Tab, Tabs, TabList, TabPanel } from 'react-tabs';
import 'react-tabs/style/react-tabs.css';

const TestPanel = props => {
  return <div>{props.children}</div>;
};

const selfLinkProps = {
  name: 'StyleguideComponent',
  params: { component: 'Tabs' },
};
  

const SectionNews = props => {
  const { rootClassName, className, currentUserListing, currentUserListingFetched } = props;

  const classes = classNames(rootClassName || css.root, className);
  return (

    
    <div className={classes}>

      <div className={css.title}>
        <FormattedMessage id="SectionNews.titleLineOne" />
      </div>

      <div className={css.steps}>
        <div className={css.step}>
          <h2 className={css.stepTitle}>
            <FormattedMessage id="SectionNews.buyer1Title" />
          </h2>
          <p>
            <FormattedMessage id="SectionNews.buyer1Text" />
          </p>
        </div>
        <div className={css.step}>
          <h2 className={css.stepTitle}>
            <FormattedMessage id="SectionNews.buyer2Title" />
          </h2>
          <p>
            <FormattedMessage id="SectionNews.buyer2Text" />
          </p>
        </div>

        <div className={css.step}>
          <h2 className={css.stepTitle}>
            <FormattedMessage id="SectionNews.buyer3Title" />
          </h2>
          <p>
            <FormattedMessage id="SectionNews.buyer3Text" />
          </p>
        </div>
      </div>
  

      
    </div>
  );
};

SectionNews.defaultProps = {
  rootClassName: null,
  className: null,
  currentUserListing: null,
  currentUserListingFetched: false,
};

SectionNews.propTypes = {
  rootClassName: string,
  className: string,
  currentUserListing: propTypes.ownListing,
  currentUserListingFetched: bool,
};

export default SectionNews;
