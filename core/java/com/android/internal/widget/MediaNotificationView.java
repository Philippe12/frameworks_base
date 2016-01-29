/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */

package com.android.internal.widget;

import android.annotation.Nullable;
import android.content.Context;
import android.util.AttributeSet;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.RelativeLayout;
import android.widget.RemoteViews;

/**
 * A TextView that can float around an image on the end.
 *
 * @hide
 */
@RemoteViews.RemoteView
public class MediaNotificationView extends RelativeLayout {

    private final int mMaxImageSize;
    private final int mImageMarginBottom;
    private final int mImageMinTopMargin;
    private final int mNotificationContentMarginEnd;
    private final int mNotificationContentImageMarginEnd;
    private ImageView mRightIcon;
    private View mActions;
    private View mHeader;

    public MediaNotificationView(Context context) {
        this(context, null);
    }

    public MediaNotificationView(Context context, @Nullable AttributeSet attrs) {
        this(context, attrs, 0);
    }

    public MediaNotificationView(Context context, @Nullable AttributeSet attrs, int defStyleAttr) {
        this(context, attrs, defStyleAttr, 0);
    }

    @Override
    protected void onMeasure(int widthMeasureSpec, int heightMeasureSpec) {
        int mode = MeasureSpec.getMode(widthMeasureSpec);
        boolean hasIcon = mRightIcon.getVisibility() != GONE;
        if (hasIcon && mode != MeasureSpec.UNSPECIFIED) {
            measureChild(mActions, widthMeasureSpec, heightMeasureSpec);
            int size = MeasureSpec.getSize(widthMeasureSpec);
            int height = MeasureSpec.getSize(heightMeasureSpec);
            size = size - mActions.getMeasuredWidth();
            ViewGroup.MarginLayoutParams layoutParams =
                    (MarginLayoutParams) mRightIcon.getLayoutParams();
            size -= layoutParams.getMarginEnd();
            size = Math.min(size, mMaxImageSize);
            size = Math.max(size, mRightIcon.getMinimumWidth());
            layoutParams.width = size;
            layoutParams.height = size;
            // because we can't allign it to the bottom with a margin, we add a topmargin to it
            layoutParams.topMargin = height - size - mImageMarginBottom;
            // If the topMargin is high enough we can also remove the header constraint!
            if (layoutParams.topMargin >= mImageMinTopMargin) {
                resetHeaderIndention();
            } else {
                int paddingEnd = mNotificationContentImageMarginEnd;
                ViewGroup.MarginLayoutParams headerParams =
                        (MarginLayoutParams) mHeader.getLayoutParams();
                headerParams.setMarginEnd(size + layoutParams.getMarginEnd());
                if (mHeader.getPaddingEnd() != paddingEnd) {
                    mHeader.setPadding(
                            isLayoutRtl() ? paddingEnd : mHeader.getPaddingLeft(),
                            mHeader.getPaddingTop(),
                            isLayoutRtl() ? mHeader.getPaddingLeft() : paddingEnd,
                            mHeader.getPaddingBottom());
                    mHeader.setLayoutParams(headerParams);
                }
            }
            mRightIcon.setLayoutParams(layoutParams);
        } else if (!hasIcon && mHeader.getPaddingEnd() != mNotificationContentMarginEnd) {
            resetHeaderIndention();
        }
        super.onMeasure(widthMeasureSpec, heightMeasureSpec);
    }

    private void resetHeaderIndention() {
        if (mHeader.getPaddingEnd() != mNotificationContentMarginEnd) {
            ViewGroup.MarginLayoutParams headerParams =
                    (MarginLayoutParams) mHeader.getLayoutParams();
            headerParams.setMarginEnd(0);
            mHeader.setPadding(
                    isLayoutRtl() ? mNotificationContentMarginEnd : mHeader.getPaddingLeft(),
                    mHeader.getPaddingTop(),
                    isLayoutRtl() ? mHeader.getPaddingLeft() : mNotificationContentMarginEnd,
                    mHeader.getPaddingBottom());
            mHeader.setLayoutParams(headerParams);
        }
    }

    public MediaNotificationView(Context context, AttributeSet attrs, int defStyleAttr,
            int defStyleRes) {
        super(context, attrs, defStyleAttr, defStyleRes);
        mMaxImageSize = context.getResources().getDimensionPixelSize(
                com.android.internal.R.dimen.media_notification_expanded_image_max_size);
        mImageMarginBottom = context.getResources().getDimensionPixelSize(
                com.android.internal.R.dimen.media_notification_expanded_image_margin_bottom);
        mImageMinTopMargin = (int) (context.getResources().getDimensionPixelSize(
                com.android.internal.R.dimen.notification_content_margin_top)
                + getResources().getDisplayMetrics().density * 2);
        mNotificationContentMarginEnd = context.getResources().getDimensionPixelSize(
                com.android.internal.R.dimen.notification_content_margin_end);
        mNotificationContentImageMarginEnd = context.getResources().getDimensionPixelSize(
                com.android.internal.R.dimen.notification_content_image_margin_end);
    }

    @Override
    protected void onFinishInflate() {
        super.onFinishInflate();
        mRightIcon = (ImageView) findViewById(com.android.internal.R.id.right_icon);
        mActions = findViewById(com.android.internal.R.id.media_actions);
        mHeader = findViewById(com.android.internal.R.id.notification_header);
    }
}
