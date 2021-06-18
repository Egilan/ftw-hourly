import React from 'react';
import PropTypes from 'prop-types';
import classNames from 'classnames';
import IconLogo from './IconLogo';
import css from './Logo.module.css';
import MobileLogoImage from './cottagedays-logo-small.png';
import DesktopLogoImage from './cottagedays-logo.png';
import LogoImage from './weddi logo 2.svg';


// const Logo = props => {
//   const { className, format, ...rest } = props;
//   const isMobile = format !== 'desktop';
//   const classes = classNames(className, { [css.logoMobile]: isMobile });
//   const logoImage = isMobile ? MobileLogoImage : DesktopLogoImage;

//   return (
//     <img
//       className={classes}
//       src={logoImage}
//       alt={config.siteTitle}
//       {...rest}
//     />
//   );
// };






const Logo = props => {
  const { className, format, ...rest } = props;
  const mobileClasses = classNames(css.logoMobile, className);
  const isMobile = format !== 'desktop';

  // If you want to use image instead of svg as a logo you can use the following code.
  // Also, remember to import the image as LogoImage here.
  // <img className={className} src={LogoImage} alt={config.siteTitle} {...rest} />



  // return (
  //   <IconLogo
  //     className={format === 'desktop' ? className : mobileClasses}
  //     format={format}
  //     {...rest}
  //   />
  // );


  if(isMobile) {
    return (
      // <img 
      //   className={css.logoMobile} 
      //   src={LogoImage} 
      //   alt={'Weddi'} 
      //   {...rest} 
      // />

    
    <IconLogo
      className={format === 'mobile' ? className : mobileClasses}
      format={format}
      {...rest}
    />
    );
  } else {
    return (
      // <img 
      //   className={css.logoDesktop} 
      //   src={LogoImage} 
      //   alt={'Weddi'} 
      //   {...rest} 
      // />

    
    <IconLogo
      className={format === 'desktop' ? className : css.logoDesktop}
      format={format}
      {...rest}
    />
    );
  };  
};

const { oneOf, string } = PropTypes;

Logo.defaultProps = {
  className: null,
  format: 'desktop',
};

Logo.propTypes = {
  className: string,
  format: oneOf(['desktop', 'mobile']),
};

export default Logo;
