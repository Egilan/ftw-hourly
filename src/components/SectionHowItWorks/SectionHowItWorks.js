// import React from 'react';
// import PropTypes from 'prop-types';
// import Tabs from './Tabs';

// const TestPanel = props => {
//   return <div>{props.children}</div>;
// };

// const { node } = PropTypes;

// TestPanel.propTypes = {
//   children: node.isRequired,
// };

// const selfLinkProps = {
//   name: 'StyleguideComponent',
//   params: { component: 'Tabs' },
// };

// const TabsWrapper = () => {
//   return (
//     <Tabs>
//       <TestPanel tabId="Description" tabLabel="Description" tabLinkProps={selfLinkProps}>
//         Description form stuff
//       </TestPanel>
//       <TestPanel selected tabId="Location" tabLabel="Location" tabLinkProps={selfLinkProps}>
//         Location form stuff
//       </TestPanel>
//       <TestPanel tabId="Price" tabLabel="Price" tabLinkProps={selfLinkProps} disabled>
//         Price form stuff
//       </TestPanel>
//     </Tabs>
//   );
// };

// export default SectionHowItWorks = {
//   component: TabsWrapper,
//   props: {},
//   group: 'navigation',
// };





import React from 'react';
import { bool, string } from 'prop-types';
import classNames from 'classnames';
import { FormattedMessage } from '../../util/reactIntl';
import { propTypes } from '../../util/types';
import { OwnListingLink } from '../../components';

import css from './SectionHowItWorks.module.css';


import { Tab, Tabs, TabList, TabPanel } from 'react-tabs';
import 'react-tabs/style/react-tabs.css';

const TestPanel = props => {
  return <div>{props.children}</div>;
};

const selfLinkProps = {
  name: 'StyleguideComponent',
  params: { component: 'Tabs' },
};
  

const SectionHowItWorks = props => {
  const { rootClassName, className, currentUserListing, currentUserListingFetched } = props;

  const classes = classNames(rootClassName || css.root, className);
  return (

    
    <div className={classes}>

      <div className={css.title}>
        <FormattedMessage id="SectionHowItWorks.titleLineOne" />
        <br />
        <FormattedMessage id="SectionHowItWorks.titleLineTwo" />
      </div>
        <Tabs>
          <TabList className={css.tabList}>
            <Tab className={css.tab}><h3>Ostajana</h3></Tab>
            <Tab className={css.tab}><h3>Myyjänä</h3></Tab>
          </TabList>

          <TabPanel>
            <div className={css.steps}>
              <div className={css.step}>
                <h2 className={css.stepTitle}>
                  <FormattedMessage id="SectionHowItWorks.buyer1Title" />
                </h2>
                <p>
                  <FormattedMessage id="SectionHowItWorks.buyer1Text" />
                </p>
              </div>
              <div className={css.step}>
                <h2 className={css.stepTitle}>
                  <FormattedMessage id="SectionHowItWorks.buyer2Title" />
                </h2>
                <p>
                  <FormattedMessage id="SectionHowItWorks.buyer2Text" />
                </p>
              </div>

              <div className={css.step}>
                <h2 className={css.stepTitle}>
                  <FormattedMessage id="SectionHowItWorks.buyer3Title" />
                </h2>
                <p>
                  <FormattedMessage id="SectionHowItWorks.buyer3Text" />
                </p>
              </div>
            </div>
          </TabPanel>
          <TabPanel>
            <div className={css.steps}>
              <div className={css.step}>
                <h2 className={css.stepTitle}>
                  <FormattedMessage id="SectionHowItWorks.seller1Title" />
                </h2>
                <p>
                  <FormattedMessage id="SectionHowItWorks.seller1Text" />
                </p>
              </div>
              <div className={css.step}>
                <h2 className={css.stepTitle}>
                  <FormattedMessage id="SectionHowItWorks.seller2Title" />
                </h2>
                <p>
                  <FormattedMessage id="SectionHowItWorks.seller2Text" />
                </p>
              </div>

              <div className={css.step}>
                <h2 className={css.stepTitle}>
                  <FormattedMessage id="SectionHowItWorks.seller3Title" />
                </h2>
                <p>
                  <FormattedMessage id="SectionHowItWorks.seller3Text" />
                </p>
              </div>
            </div>
          </TabPanel>
        </Tabs>

      


      {/* <Tabs>
        <TestPanel tabId="Buyer" tabLabel="Ostaja" tabLinkProps={selfLinkProps}>
          <div className={css.steps}>
            <div className={css.step}>
              <h2 className={css.stepTitle}>
                <FormattedMessage id="SectionHowItWorks.part1Title" />
              </h2>
              <p>
                <FormattedMessage id="SectionHowItWorks.part1Text" />
              </p>
            </div>

            <div className={css.step}>
              <h2 className={css.stepTitle}>
                <FormattedMessage id="SectionHowItWorks.part2Title" />
              </h2>
              <p>
                <FormattedMessage id="SectionHowItWorks.part2Text" />
              </p>
            </div>

            <div className={css.step}>
              <h2 className={css.stepTitle}>
                <FormattedMessage id="SectionHowItWorks.part3Title" />
              </h2>
              <p>
                <FormattedMessage id="SectionHowItWorks.part3Text" />
              </p>
            </div>
          </div>
        </TestPanel>
        <TestPanel selected tabId="Seller" tabLabel="Myyjä" tabLinkProps={selfLinkProps}>
          <div className={css.steps}>
            <div className={css.step}>
              <h2 className={css.stepTitle}>
                <FormattedMessage id="SectionHowItWorks.part1Title" />
              </h2>
              <p>
                <FormattedMessage id="SectionHowItWorks.part1Text" />
              </p>
            </div>

            <div className={css.step}>
              <h2 className={css.stepTitle}>
                <FormattedMessage id="SectionHowItWorks.part2Title" />
              </h2>
              <p>
                <FormattedMessage id="SectionHowItWorks.part2Text" />
              </p>
            </div>

            <div className={css.step}>
              <h2 className={css.stepTitle}>
                <FormattedMessage id="SectionHowItWorks.part3Title" />
              </h2>
              <p>
                <FormattedMessage id="SectionHowItWorks.part3Text" />
              </p>
            </div>
          </div>
        </TestPanel>
      </Tabs> */}



      

      
      <div className={css.createListingLink}>
        <OwnListingLink listing={currentUserListing} listingFetched={currentUserListingFetched}>
          <FormattedMessage id="SectionHowItWorks.createListingLink" />
        </OwnListingLink>
      </div>
    </div>
  );
};

SectionHowItWorks.defaultProps = {
  rootClassName: null,
  className: null,
  currentUserListing: null,
  currentUserListingFetched: false,
};

SectionHowItWorks.propTypes = {
  rootClassName: string,
  className: string,
  currentUserListing: propTypes.ownListing,
  currentUserListingFetched: bool,
};

export default SectionHowItWorks;
