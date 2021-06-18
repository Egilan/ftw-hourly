import React from 'react';
import config from '../../config';
import { twitterPageURL } from '../../util/urlHelpers';
import { StaticPage, TopbarContainer } from '../../containers';
import {
  LayoutSingleColumn,
  LayoutWrapperTopbar,
  LayoutWrapperMain,
  LayoutWrapperFooter,
  Footer,
  ExternalLink,
} from '../../components';

import css from './AboutPage.module.css';
import image from './about-us.jpg';

const AboutPage = () => {
  const { siteTwitterHandle, siteFacebookPage } = config;
  const siteTwitterPage = twitterPageURL(siteTwitterHandle);

  // prettier-ignore
  return (
    <StaticPage
      title="About Us"
      schema={{
        '@context': 'http://schema.org',
        '@type': 'AboutPage',
        description: 'Mikä on Weddi?',
        name: 'Tietoa Weddistä',
      }}
    >
      <LayoutSingleColumn>
        <LayoutWrapperTopbar>
          <TopbarContainer />
        </LayoutWrapperTopbar>

        <LayoutWrapperMain className={css.staticPageWrapper}>
          <h1 className={css.pageTitle}>Löydä unelmiesi häät Weddistä</h1>
          <img className={css.coverImage} src={image} alt="My first ice cream." />

          <div className={css.contentWrapper}>
            <div className={css.contentSide}>
              <p>Häiden järjestäminen saattaa stressata. Meidän tehtävämme on minimoida se.</p>
            </div>

            <div className={css.contentMain}>
              <h2>
                Jokainen haluaa itselleen omannäköiset häät. Kuitenkin tämä toive saattaa olla vaikea toteuttaa. 
                Tietoa on valtavasti, se on ympäriinsä: nettisivuilla, messuilla, blogeissa, lehdissä.
              </h2>

              <p>
                Weddin tehtävä on tuoda kaikki tämä tieto yhden sivuston alle. Aloitamme kuitenkin palveluntarjoajista.
                Tavoitteenamme on luoda sivusto kaikille hääpalveluiden tuottajille, jolta he voivat parhaiten tavoittaa asiakkaansa.
                
              </p>

              <h3 className={css.subtitle}>Oletko hääpalveluiden tuottaja?</h3>

              <p>
                Weddi tarjoaa sinulle ja yrityksellesi kätevän markkinapaikan tuoda palvelusi esille hyvässä valossa ja tavoittaa asiakkaat.
                Voit vähentää markkinointikulujasi ja jopa löytää täysin uusia asiakassegmenttejä Weddin avulla. 
                Hääpalveluiden varauksessa ongelma on useimmiten luottamus, sillä kaiken pitää mennä nappiin juuri sinä tiettynä päivänä.
                Weddi tukee tapoja, joilla asiakkaat voivat luottavaisin mielin ostaa palveluitasi.
              </p>
              <p>
                Voit myös tykätä meistä {' '}
                <ExternalLink href={siteFacebookPage}>Facebookissa</ExternalLink> ja seurata{' '}
                <ExternalLink href={siteTwitterPage}>Twitterissä</ExternalLink>.
              </p>
            </div>
          </div>
        </LayoutWrapperMain>

        <LayoutWrapperFooter>
          <Footer />
        </LayoutWrapperFooter>
      </LayoutSingleColumn>
    </StaticPage>
  );
};

export default AboutPage;
